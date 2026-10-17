//! commons `TopologicalUtil`: dependency waves for a transport import, so an object is saved
//! after the same-type objects it refers to.

use std::collections::{HashMap, HashSet};

use indexmap::{IndexMap, IndexSet};

/// The waves in order (items in one wave are independent of each other) and what could not be
/// ordered: members of a cycle and anything waiting behind one.
#[derive(Debug, Clone, PartialEq)]
pub struct Ordered<T> {
    pub waves: Vec<Vec<T>>,
    pub cyclic: Vec<T>,
}

/// Kahn's algorithm by levels. Dependencies on keys outside `items` are dropped; a self
/// dependency is kept (the item comes back in `cyclic`); items with no key go in the first
/// wave; order inside a wave and in `cyclic` follows the input.
pub fn sort<T: Clone>(items: &[T], key: impl Fn(&T) -> Option<String>, deps: impl Fn(&T) -> Vec<String>) -> Ordered<T> {
    if items.is_empty() {
        return Ordered { waves: Vec::new(), cyclic: Vec::new() };
    }
    let mut by_key: IndexMap<String, Vec<T>> = IndexMap::new();
    let mut unkeyed = Vec::new();
    for item in items {
        match key(item) {
            Some(k) => by_key.entry(k).or_default().push(item.clone()),
            None => unkeyed.push(item.clone()),
        }
    }
    let mut depends_on: HashMap<String, HashSet<String>> = HashMap::new();
    let mut dependents: HashMap<String, Vec<String>> = HashMap::new();
    for (k, group) in &by_key {
        let resolved: HashSet<String> = group.iter().flat_map(&deps).filter(|d| by_key.contains_key(d)).collect();
        for d in &resolved {
            dependents.entry(d.clone()).or_default().push(k.clone());
        }
        depends_on.insert(k.clone(), resolved);
    }
    let mut waves: Vec<Vec<T>> = Vec::new();
    let mut pending: IndexSet<String> = by_key.keys().cloned().collect();
    while !pending.is_empty() {
        let ready: Vec<String> = pending.iter().filter(|k| depends_on.get(*k).is_none_or(HashSet::is_empty)).cloned().collect();
        if ready.is_empty() {
            break;
        }
        let mut wave = Vec::new();
        for k in &ready {
            wave.extend(by_key.get(k).cloned().unwrap_or_default());
            pending.shift_remove(k);
            for d in dependents.get(k).cloned().unwrap_or_default() {
                if let Some(set) = depends_on.get_mut(&d) {
                    set.remove(k);
                }
            }
        }
        waves.push(wave);
    }
    if !unkeyed.is_empty() {
        match waves.first_mut() {
            Some(first) => first.extend(unkeyed),
            None => waves.push(unkeyed),
        }
    }
    let cyclic = pending.iter().flat_map(|k| by_key.get(k).cloned().unwrap_or_default()).collect();
    Ordered { waves, cyclic }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Item = (Option<&'static str>, Vec<&'static str>);

    fn run(items: &[Item]) -> Ordered<Item> {
        sort(items, |i| i.0.map(str::to_string), |i| i.1.iter().map(|s| s.to_string()).collect())
    }

    fn names(w: &[Item]) -> Vec<&'static str> {
        w.iter().map(|i| i.0.unwrap_or("-")).collect()
    }

    #[test]
    fn waves_cycles_and_strays() {
        assert_eq!(run(&[]).waves.len(), 0);
        let o = run(&[(Some("b"), vec!["a"]), (Some("a"), vec!["zzz"]), (Some("c"), vec!["b", "a"]), (None, vec![])]);
        let w: Vec<Vec<&str>> = o.waves.iter().map(|w| names(w)).collect();
        assert_eq!(w, vec![vec!["a", "-"], vec!["b"], vec!["c"]]);
        assert!(o.cyclic.is_empty());
        let o = run(&[(Some("x"), vec!["y"]), (Some("y"), vec!["x"]), (Some("z"), vec!["x"]), (Some("s"), vec!["s"]), (Some("ok"), vec![])]);
        assert_eq!(names(&o.waves[0]), ["ok"]);
        assert_eq!(names(&o.cyclic), ["x", "y", "z", "s"]);
        let o = run(&[(None, vec![]), (Some("d"), vec!["e"]), (Some("e"), vec!["d"])]);
        assert_eq!(names(&o.waves[0]), ["-"], "unkeyed items make a wave of their own when nothing else can go");
        let o = run(&[(Some("dup"), vec![]), (Some("dup"), vec![])]);
        assert_eq!(o.waves[0].len(), 2, "a repeated key keeps both items");
    }
}
