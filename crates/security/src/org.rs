//! `OrgStructure`: a client's reporting tree, built from one scan of its users and walked in
//! memory.
//!
//! The order of `subOrg` is a breadth-first walk where each manager's reports come in the
//! iteration order of Java's `new HashMap<>(managerOf)`, which is what Java returns.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::javamap::{copy_order, iteration_order, long_hash};

#[derive(Debug, Clone, Default)]
pub struct OrgStructure {
    manager_of: HashMap<u64, Option<u64>>,
    reports_of: HashMap<u64, Vec<u64>>,
    inactive: HashSet<u64>,
}

impl OrgStructure {
    /// `OrgStructureService.load`: (user, reports to, status) rows in the order the database
    /// returned them.
    pub fn new(edges: &[(u64, Option<u64>, Option<String>)]) -> Self {
        let mut manager_of = HashMap::new();
        let mut inserted = Vec::new();
        let mut inactive = HashSet::new();
        for (user, manager, status) in edges {
            if manager_of.insert(*user, *manager).is_none() {
                inserted.push(*user);
            }
            if status.as_deref().is_some_and(|s| s != "ACTIVE") {
                inactive.insert(*user);
            }
        }
        let source = iteration_order(inserted.into_iter().map(|u| (long_hash(u), u)).collect());
        let copy = copy_order(source.into_iter().map(|u| (long_hash(u), u)).collect());
        let mut reports_of: HashMap<u64, Vec<u64>> = HashMap::new();
        for user in copy {
            if let Some(Some(manager)) = manager_of.get(&user) {
                reports_of.entry(*manager).or_default().push(user);
            }
        }
        Self { manager_of, reports_of, inactive }
    }

    /// Everyone who reports to `user_id`, directly or not, breadth first.
    pub fn sub_org(&self, user_id: u64, include_self: bool) -> Vec<u64> {
        let mut found: Vec<u64> = Vec::new();
        let mut seen = HashSet::new();
        let mut pending = VecDeque::from([user_id]);
        while let Some(current) = pending.pop_front() {
            if !seen.insert(current) {
                continue;
            }
            found.push(current);
            if let Some(reports) = self.reports_of.get(&current) {
                pending.extend(reports.iter().copied());
            }
        }
        if !include_self {
            found.retain(|u| *u != user_id);
        }
        found
    }

    pub fn contains(&self, user_id: u64) -> bool {
        self.manager_of.contains_key(&user_id)
    }

    pub fn is_active(&self, user_id: u64) -> bool {
        self.contains(user_id) && !self.inactive.contains(&user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(u: u64, m: Option<u64>, s: &str) -> (u64, Option<u64>, Option<String>) {
        (u, m, Some(s.to_string()))
    }

    #[test]
    fn breadth_first_with_java_map_order() {
        // 10 manages 30, 20, 25 (database order); 20 manages 40; 40 manages 10 (a cycle).
        let t = OrgStructure::new(&[
            edge(10, Some(40), "ACTIVE"),
            edge(30, Some(10), "ACTIVE"),
            edge(20, Some(10), "INACTIVE"),
            edge(25, Some(10), "ACTIVE"),
            edge(40, Some(20), "ACTIVE"),
            edge(50, None, "ACTIVE"),
        ]);
        // Six keys: the copy has 8 buckets, so 10's reports come as 25 (bucket 1), 20 (4), 30 (6).
        assert_eq!(t.sub_org(10, true), vec![10, 25, 20, 30, 40]);
        assert_eq!(t.sub_org(10, false), vec![25, 20, 30, 40]);
        assert_eq!(t.sub_org(50, true), vec![50]);
        assert_eq!(t.sub_org(99, true), vec![99]);
        assert!(t.contains(20) && !t.is_active(20) && t.is_active(30) && !t.is_active(99));
    }

    // OrgStructureTest: the ten-level chain with a branch, 20 a second root, 9 inactive.
    fn deep_tree() -> (Vec<(u64, Option<u64>, Option<String>)>, OrgStructure) {
        let pairs: [(u64, Option<u64>); 16] = [
            (1, None), (2, Some(1)), (3, Some(1)), (4, Some(2)), (5, Some(3)), (6, Some(4)), (7, Some(5)), (8, Some(6)),
            (9, Some(7)), (10, Some(8)), (11, Some(9)), (12, Some(10)), (14, Some(12)), (16, Some(14)), (18, Some(16)), (20, None),
        ];
        let edges: Vec<_> = pairs.iter().map(|(u, m)| edge(*u, *m, if *u == 9 { "INACTIVE" } else { "ACTIVE" })).collect();
        let t = OrgStructure::new(&edges);
        (edges, t)
    }

    #[test]
    fn matches_the_walk_it_replaced() {
        let (edges, t) = deep_tree();
        for (root, _, _) in &edges {
            // The per-node walk: everyone reachable through the reports, as a set.
            let mut want = vec![*root];
            let mut i = 0;
            while i < want.len() {
                let cur = want[i];
                want.extend(edges.iter().filter(|(_, m, _)| *m == Some(cur)).map(|(u, _, _)| *u));
                i += 1;
            }
            let mut got = t.sub_org(*root, true);
            got.sort();
            want.sort();
            assert_eq!(got, want, "from {root}");
            assert!(!t.sub_org(*root, false).contains(root));
        }
    }

    #[test]
    fn status_is_carried_but_never_filters_and_unknowns_fail_closed() {
        let (_, t) = deep_tree();
        assert!(t.sub_org(7, true).contains(&9), "reads must not change");
        assert!(!t.is_active(9) && t.is_active(7));
        assert!(!t.contains(999) && !t.is_active(999));
        assert_eq!(t.sub_org(20, true), vec![20], "a root reporting to nobody is its own whole tree");
    }

    #[test]
    fn survives_a_cycle() {
        let t = OrgStructure::new(&[edge(1, Some(2), "ACTIVE"), edge(2, Some(3), "ACTIVE"), edge(3, Some(1), "ACTIVE")]);
        assert_eq!(t.sub_org(1, true).len(), 3);
    }
}
