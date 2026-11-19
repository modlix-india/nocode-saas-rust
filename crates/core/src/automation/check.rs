//! Whether an automation can run as drawn: what the editor lists under "Fix these" and what
//! publishing refuses on. A draft may be saved with errors; it may not go live with them.
//!
//! The messages are for the person who drew the flow, so they name a step by its title and
//! say what to do, never a field path.

use std::collections::{BTreeMap, BTreeSet};

use overridable::pojo::{map_field, str_field};
use overridable::{JMap, JValue};

use super::{period_seconds, ACTION, BRANCH_OTHERWISE, BRANCH_YES, CHECK, END, JOIN, NODE_TYPES, SPLIT, WAIT};

/// One thing wrong, or worth a second look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable, for the editor to key its own wording or highlight on.
    pub code: &'static str,
    /// The step it is about, when it is about one.
    pub node: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub errors: Vec<Finding>,
    pub warnings: Vec<Finding>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }

    /// `{ ok, errors: [{code, node, message}], warnings: [...] }`.
    pub fn to_json(&self) -> JValue {
        let list = |l: &[Finding]| {
            JValue::Array(
                l.iter()
                    .map(|f| {
                        let mut m = JMap::new();
                        m.insert("code".into(), JValue::Str(f.code.into()));
                        m.insert("node".into(), f.node.clone().map(JValue::Str).unwrap_or(JValue::Null));
                        m.insert("message".into(), JValue::Str(f.message.clone()));
                        JValue::Object(m)
                    })
                    .collect(),
            )
        };
        let mut m = JMap::new();
        m.insert("ok".into(), JValue::Bool(self.ok()));
        m.insert("errors".into(), list(&self.errors));
        m.insert("warnings".into(), list(&self.warnings));
        JValue::Object(m)
    }

    fn error(&mut self, code: &'static str, node: Option<&str>, message: String) {
        self.errors.push(Finding { code, node: node.map(str::to_string), message });
    }

    fn warning(&mut self, code: &'static str, node: Option<&str>, message: String) {
        self.warnings.push(Finding { code, node: node.map(str::to_string), message });
    }
}

fn filled(v: Option<&JValue>) -> bool {
    match v {
        None | Some(JValue::Null) => false,
        Some(JValue::Str(s)) => !s.trim().is_empty(),
        Some(JValue::Object(m)) => !m.is_empty(),
        Some(_) => true,
    }
}

struct Edge<'a> {
    to: &'a str,
    branch: Option<&'a str>,
}

/// The flow as the checks walk it: each node's type and title, and its ways out.
struct Graph<'a> {
    kinds: BTreeMap<&'a str, &'a str>,
    titles: BTreeMap<&'a str, String>,
    out: BTreeMap<&'a str, Vec<Edge<'a>>>,
    incoming: BTreeMap<&'a str, usize>,
}

impl<'a> Graph<'a> {
    fn title(&self, key: &str) -> String {
        self.titles.get(key).cloned().unwrap_or_else(|| key.to_string())
    }

    fn next(&self, key: &str) -> impl Iterator<Item = &'a str> + '_ {
        self.out.get(key).into_iter().flatten().map(|e| e.to)
    }

    /// Every node reachable from `from` (itself included), not walking through `stop` kinds.
    fn reach(&self, from: &'a str, stop: &[&str]) -> BTreeSet<&'a str> {
        let mut seen = BTreeSet::new();
        let mut todo = vec![from];
        while let Some(k) = todo.pop() {
            if !seen.insert(k) {
                continue;
            }
            if k != from && self.kinds.get(k).is_some_and(|t| stop.contains(t)) {
                continue;
            }
            todo.extend(self.next(k));
        }
        seen
    }
}

/// Checks the whole document.
pub fn check(doc: &JMap) -> Report {
    let mut r = Report::default();

    if !filled(map_field(doc, "trigger").and_then(|t| t.get("key"))) {
        r.error("TRIGGER_MISSING", None, "Choose what starts this automation.".into());
    }

    let empty = JMap::new();
    let nodes = map_field(doc, "nodes").unwrap_or(&empty);
    if nodes.is_empty() {
        r.error("NO_STEPS", None, "Add at least one step.".into());
        return r;
    }

    let mut g = Graph { kinds: BTreeMap::new(), titles: BTreeMap::new(), out: BTreeMap::new(), incoming: BTreeMap::new() };
    for (key, node) in nodes {
        let Some(n) = node.as_object() else {
            r.error("STEP_UNREADABLE", Some(key), format!("The step \"{key}\" could not be read. Remove it and add it again."));
            continue;
        };
        let title = str_field(n, "title").map(str::trim).filter(|t| !t.is_empty()).unwrap_or(key).to_string();
        match str_field(n, "type") {
            Some(t) if NODE_TYPES.contains(&t) => {
                g.kinds.insert(key.as_str(), NODE_TYPES.iter().find(|k| **k == t).copied().unwrap_or(END));
            }
            _ => {
                r.error("STEP_TYPE", Some(key), format!("The step \"{title}\" has no kind. Remove it and add it again."));
                continue;
            }
        }
        g.titles.insert(key.as_str(), title);
    }

    transitions(doc, &mut g, &mut r);
    for (key, node) in nodes {
        if let (Some(n), Some(kind)) = (node.as_object(), g.kinds.get(key.as_str())) {
            node_rules(key, kind, n, &g, &mut r);
        }
    }

    match str_field(doc, "start") {
        Some(s) if g.kinds.contains_key(s) => {
            let reached = g.reach(s, &[]);
            for key in g.kinds.keys().filter(|k| !reached.contains(**k)) {
                r.error("STEP_UNREACHABLE", Some(key), format!("The step \"{}\" is not connected to the flow, so it would never run.", g.title(key)));
            }
        }
        _ => r.error("START_MISSING", None, "Choose the first step.".into()),
    }

    loops(&g, &mut r);
    lanes(&g, &mut r);
    r
}

/// Reads `transitions` into the graph, refusing the ones that point nowhere.
fn transitions<'a>(doc: &'a JMap, g: &mut Graph<'a>, r: &mut Report) {
    let list = match doc.get("transitions") {
        Some(JValue::Array(a)) => a.as_slice(),
        None | Some(JValue::Null) => &[],
        Some(_) => {
            r.error("LINKS_UNREADABLE", None, "The links between the steps could not be read.".into());
            &[]
        }
    };
    for t in list {
        let (Some(from), Some(to)) = (t.as_object().and_then(|m| str_field(m, "from")), t.as_object().and_then(|m| str_field(m, "to"))) else {
            r.error("LINK_UNREADABLE", None, "A link between two steps could not be read.".into());
            continue;
        };
        let (Some((&from, _)), Some((&to, _))) = (g.kinds.get_key_value(from), g.kinds.get_key_value(to)) else {
            r.error("LINK_DANGLING", None, format!("A link goes from \"{from}\" to \"{to}\", and one of them is not a step any more."));
            continue;
        };
        let branch = t.as_object().and_then(|m| str_field(m, "branch")).filter(|b| !b.is_empty());
        g.out.entry(from).or_default().push(Edge { to, branch });
        *g.incoming.entry(to).or_default() += 1;
    }
}

/// What each kind of step needs, and how many ways out it may have.
fn node_rules(key: &str, kind: &str, n: &JMap, g: &Graph, r: &mut Report) {
    let title = g.title(key);
    let out = g.out.get(key).map(Vec::as_slice).unwrap_or(&[]);
    match kind {
        ACTION => {
            if !filled(n.get("action")) {
                r.error("ACTION_MISSING", Some(key), format!("Choose what the step \"{title}\" does."));
            }
        }
        WAIT => {
            let set: Vec<&str> = ["for", "until", "untilEvent"].into_iter().filter(|f| filled(n.get(*f))).collect();
            match set.as_slice() {
                [] => r.error("WAIT_EMPTY", Some(key), format!("Say how long \"{title}\" waits.")),
                [one] => {
                    if *one == "for" && str_field(n, "for").and_then(period_seconds).is_none() {
                        r.error("WAIT_PERIOD", Some(key), format!("The waiting time of \"{title}\" is not a length of time."));
                    }
                    if *one == "untilEvent" {
                        if !filled(map_field(n, "untilEvent").and_then(|e| e.get("key"))) {
                            r.error("WAIT_EVENT", Some(key), format!("Choose what \"{title}\" waits for."));
                        }
                        match n.get("timeout") {
                            None | Some(JValue::Null) => r.warning(
                                "WAIT_NO_LIMIT",
                                Some(key),
                                format!("\"{title}\" has no time limit. If what it waits for never happens, it waits for ever."),
                            ),
                            Some(JValue::Str(t)) if period_seconds(t).is_some() => {}
                            Some(_) => r.error("WAIT_LIMIT", Some(key), format!("The time limit of \"{title}\" is not a length of time.")),
                        }
                    }
                }
                _ => r.error("WAIT_AMBIGUOUS", Some(key), format!("\"{title}\" waits in more than one way. Keep one.")),
            }
        }
        CHECK => {
            if !filled(n.get("condition")) {
                r.error("CHECK_EMPTY", Some(key), format!("Say what \"{title}\" checks."));
            }
            for b in [BRANCH_YES, BRANCH_OTHERWISE] {
                if out.iter().filter(|e| e.branch == Some(b)).count() > 1 {
                    r.error("CHECK_BRANCH_TWICE", Some(key), format!("\"{title}\" has two \"{b}\" paths. Keep one."));
                }
            }
            if out.iter().any(|e| !matches!(e.branch, Some(BRANCH_YES) | Some(BRANCH_OTHERWISE))) {
                r.error("CHECK_BRANCH", Some(key), format!("A path out of \"{title}\" is neither its \"yes\" nor its \"otherwise\"."));
            }
            if out.is_empty() {
                r.warning("CHECK_LEADS_NOWHERE", Some(key), format!("Nothing follows \"{title}\", so checking changes nothing."));
            }
        }
        SPLIT => {
            if out.len() < 2 {
                r.error("SPLIT_LANES", Some(key), format!("\"{title}\" needs at least two things to do at the same time."));
            }
        }
        JOIN => {
            if g.incoming.get(key).copied().unwrap_or(0) < 2 {
                r.warning("JOIN_ONE_LANE", Some(key), format!("\"{title}\" brings only one path together."));
            }
        }
        END => {
            if !out.is_empty() {
                r.error("END_CONTINUES", Some(key), format!("\"{title}\" ends the automation, so nothing can follow it."));
            }
        }
        _ => {}
    }
    if matches!(kind, ACTION | WAIT | JOIN) && out.len() > 1 {
        r.error("TOO_MANY_PATHS", Some(key), format!("\"{title}\" leads to more than one step. To do things at the same time, add \"At the same time\"."));
    }
}

/// A loop is allowed only when it passes through a wait: one without would run for ever, at
/// once. Found by walking the flow with the waits taken out.
fn loops(g: &Graph, r: &mut Report) {
    // 0 unseen, 1 on the walk, 2 done.
    let mut state: BTreeMap<&str, u8> = BTreeMap::new();
    let mut reported: BTreeSet<&str> = BTreeSet::new();
    for start in g.kinds.keys().copied() {
        if g.kinds[start] == WAIT || state.get(start).copied().unwrap_or(0) != 0 {
            continue;
        }
        // (node, index of the next way out to try)
        let mut stack: Vec<(&str, usize)> = vec![(start, 0)];
        state.insert(start, 1);
        while let Some((k, i)) = stack.last().copied() {
            let ways: Vec<&str> = g.next(k).filter(|n| g.kinds[*n] != WAIT).collect();
            if i >= ways.len() {
                state.insert(k, 2);
                stack.pop();
                continue;
            }
            stack.last_mut().expect("just read").1 += 1;
            let n = ways[i];
            match state.get(n).copied().unwrap_or(0) {
                0 => {
                    state.insert(n, 1);
                    stack.push((n, 0));
                }
                1 if reported.insert(n) => {
                    r.error(
                        "LOOP_WITHOUT_WAIT",
                        Some(n),
                        format!("The flow comes back to \"{}\" without waiting, so it would repeat without end. Add a wait inside the loop.", g.title(n)),
                    );
                }
                _ => {}
            }
        }
    }
}

/// Every lane a split starts has to arrive at one same join, or the lanes never come together.
fn lanes(g: &Graph, r: &mut Report) {
    for (key, _) in g.kinds.iter().filter(|(_, t)| **t == SPLIT) {
        let lanes: Vec<&str> = g.next(key).collect();
        if lanes.len() < 2 {
            continue;
        }
        let mut common: Option<BTreeSet<&str>> = None;
        let mut any_join = false;
        for lane in &lanes {
            let joins: BTreeSet<&str> = g.reach(lane, &[JOIN]).into_iter().filter(|k| g.kinds[*k] == JOIN).collect();
            any_join |= !joins.is_empty();
            common = Some(match common {
                None => joins,
                Some(c) => c.intersection(&joins).copied().collect(),
            });
        }
        // Lanes that all simply end are fine: nothing has to wait for them.
        if any_join && common.is_none_or(|c| c.is_empty()) {
            r.error(
                "SPLIT_NOT_JOINED",
                Some(key),
                format!("The paths out of \"{}\" do not all come back together at the same place.", g.title(key)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(text: &str) -> JMap {
        match overridable::json::parse(text.as_bytes()).expect("json") {
            JValue::Object(m) => m,
            _ => panic!("not an object"),
        }
    }

    fn codes(l: &[Finding]) -> Vec<&'static str> {
        l.iter().map(|f| f.code).collect()
    }

    /// Deal created, send, wait two days or until read, check, two endings.
    const FOLLOW_UP: &str = r#"{
        "trigger": {"key": "LZ_DEAL_CREATED"},
        "start": "welcome",
        "nodes": {
            "welcome": {"type": "ACTION", "title": "Send welcome", "action": "LeadZumpV2.whatsappTemplateSend", "params": {"template": "welcome"}},
            "hold": {"type": "WAIT", "title": "Wait for a read", "untilEvent": {"key": "LZ_WA_STATUS"}, "timeout": "P2D"},
            "read": {"type": "CHECK", "title": "Was it read", "condition": {"operator": "AND", "conditions": [{"field": "hold.status", "operator": "EQUALS", "value": "read"}]}},
            "task": {"type": "ACTION", "title": "Create task", "action": "LeadZumpV2.taskCreate"},
            "again": {"type": "ACTION", "title": "Send reminder", "action": "LeadZumpV2.whatsappTemplateSend"},
            "done": {"type": "END"}
        },
        "transitions": [
            {"from": "welcome", "to": "hold"},
            {"from": "hold", "to": "read"},
            {"from": "read", "to": "task", "branch": "yes"},
            {"from": "read", "to": "again", "branch": "otherwise"},
            {"from": "task", "to": "done"},
            {"from": "again", "to": "done"}
        ]
    }"#;

    #[test]
    fn a_sound_flow_passes() {
        let r = check(&doc(FOLLOW_UP));
        assert!(r.ok(), "{:?}", r.errors);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let j = r.to_json();
        assert_eq!(j.as_object().unwrap()["ok"].as_bool(), Some(true));
    }

    #[test]
    fn nothing_drawn_yet() {
        let r = check(&doc("{}"));
        assert_eq!(codes(&r.errors), vec!["TRIGGER_MISSING", "NO_STEPS"]);
        let r = check(&doc(r#"{"trigger":{"key":" "},"nodes":{"a":{"type":"END"}}}"#));
        assert_eq!(codes(&r.errors), vec!["TRIGGER_MISSING", "START_MISSING"]);
        let r = check(&doc(r#"{"trigger":{"key":"E"},"start":"gone","nodes":{"a":{"type":"END"}}}"#));
        assert_eq!(codes(&r.errors), vec!["START_MISSING"]);
    }

    #[test]
    fn steps_that_cannot_run() {
        let r = check(&doc(
            r#"{"trigger":{"key":"E"},"start":"a","nodes":{
                "a":{"type":"ACTION"},
                "b":{"type":"NOPE","title":"Odd"},
                "c":7,
                "d":{"type":"CHECK","title":"Ask"},
                "e":{"type":"ACTION","action":"x","title":"Lost"}
            },"transitions":[{"from":"a","to":"d"},{"from":"d","to":"a","branch":"maybe"},{"from":"a","to":"zz"},{"to":"a"}]}"#,
        ));
        let c = codes(&r.errors);
        for want in ["STEP_TYPE", "STEP_UNREADABLE", "ACTION_MISSING", "CHECK_EMPTY", "CHECK_BRANCH", "LINK_DANGLING", "LINK_UNREADABLE", "STEP_UNREACHABLE", "LOOP_WITHOUT_WAIT"] {
            assert!(c.contains(&want), "{want} missing from {c:?}");
        }
        let lost = r.errors.iter().find(|f| f.code == "STEP_UNREACHABLE").unwrap();
        assert_eq!(lost.node.as_deref(), Some("e"));
        assert!(lost.message.contains("\"Lost\""), "{}", lost.message);
    }

    #[test]
    fn waits() {
        let w = |body: &str| {
            let d = format!(r#"{{"trigger":{{"key":"E"}},"start":"w","nodes":{{"w":{{"type":"WAIT",{body}}}}}}}"#);
            let r = check(&doc(&d));
            (codes(&r.errors), codes(&r.warnings))
        };
        assert_eq!(w(r#""for":"P2D""#), (vec![], vec![]));
        assert_eq!(w(r#""until":"{{deal.visitAt}}""#), (vec![], vec![]));
        assert_eq!(w(r#""title":"x""#), (vec!["WAIT_EMPTY"], vec![]));
        assert_eq!(w(r#""for":"two days""#), (vec!["WAIT_PERIOD"], vec![]));
        assert_eq!(w(r#""for":"P1D","until":"x""#), (vec!["WAIT_AMBIGUOUS"], vec![]));
        assert_eq!(w(r#""untilEvent":{"key":"E"}"#), (vec![], vec!["WAIT_NO_LIMIT"]));
        assert_eq!(w(r#""untilEvent":{"key":"E"},"timeout":"soon""#), (vec!["WAIT_LIMIT"], vec![]));
        assert_eq!(w(r#""untilEvent":{"filter":{"a":1}},"timeout":"PT1H""#), (vec!["WAIT_EVENT"], vec![]));
    }

    #[test]
    fn a_loop_needs_a_wait() {
        let looped = |wait: &str| {
            format!(
                r#"{{"trigger":{{"key":"E"}},"start":"a","nodes":{{
                    "a":{{"type":"ACTION","action":"x","title":"Remind"}},
                    "w":{{"type":"{wait}","for":"P1D","action":"x"}},
                    "c":{{"type":"CHECK","condition":{{"operator":"AND"}}}}
                }},"transitions":[{{"from":"a","to":"w"}},{{"from":"w","to":"c"}},{{"from":"c","to":"a","branch":"otherwise"}}]}}"#
            )
        };
        assert!(check(&doc(&looped("WAIT"))).ok());
        let r = check(&doc(&looped("ACTION")));
        assert_eq!(codes(&r.errors), vec!["LOOP_WITHOUT_WAIT"]);
    }

    #[test]
    fn lanes_come_back_together() {
        let split = |extra_nodes: &str, links: &str| {
            format!(
                r#"{{"trigger":{{"key":"E"}},"start":"s","nodes":{{
                    "s":{{"type":"SPLIT","title":"Both"}},
                    "a":{{"type":"ACTION","action":"x"}},
                    "b":{{"type":"ACTION","action":"y"}}{extra_nodes}
                }},"transitions":[{{"from":"s","to":"a"}},{{"from":"s","to":"b"}}{links}]}}"#
            )
        };
        // Both lanes simply end.
        assert!(check(&doc(&split("", ""))).ok());
        // Both arrive at one join.
        let joined = split(r#","j":{"type":"JOIN"},"z":{"type":"END"}"#, r#",{"from":"a","to":"j"},{"from":"b","to":"j"},{"from":"j","to":"z"}"#);
        let r = check(&doc(&joined));
        assert!(r.ok() && r.warnings.is_empty(), "{r:?}");
        // One lane joins, the other never arrives.
        let half = split(r#","j":{"type":"JOIN"}"#, r#",{"from":"a","to":"j"}"#);
        let r = check(&doc(&half));
        assert_eq!(codes(&r.errors), vec!["SPLIT_NOT_JOINED"]);
        assert_eq!(codes(&r.warnings), vec!["JOIN_ONE_LANE"]);
        // A split with one lane, an action with two ways out, an end that goes on.
        let r = check(&doc(
            r#"{"trigger":{"key":"E"},"start":"s","nodes":{"s":{"type":"SPLIT"},"a":{"type":"ACTION","action":"x"},"e":{"type":"END"},"f":{"type":"END"}},
                "transitions":[{"from":"s","to":"a"},{"from":"a","to":"e"},{"from":"a","to":"f"},{"from":"e","to":"f"}]}"#,
        ));
        assert_eq!(codes(&r.errors), vec!["SPLIT_LANES", "TOO_MANY_PATHS", "END_CONTINUES"]);
    }
}
