//! The iteration order of a `java.util.HashMap` / `HashSet`, for the few places where Java's
//! output order is whatever its hash table yields (JWT claims, `Collectors.groupingBy`,
//! `Collectors.toSet`).
//!
//! A `HashMap` starts with 16 buckets and doubles when its size passes 3/4 of that. A key
//! lands in bucket `(h ^ (h >>> 16)) & (capacity - 1)`; iteration walks the buckets in order. How
//! a bucket is ordered depends on how keys went in:
//! - `put` (a `HashSet`, a claims map) appends to the bucket and grows the table after an
//!   insertion takes it over the threshold;
//! - `computeIfAbsent` (`Collectors.groupingBy`) puts the new key at the head of its bucket, and
//!   grows the table before an insertion when it is already over.
//!
//! A resize splits each bucket without reordering it, so the final order is fixed by the final
//! size alone. Eight or more keys in one bucket (which grows a small table early, or makes a tree
//! bin) are not modelled: ids and claim names never get there.

use platform::java::string_hash_code;

/// `Long.hashCode()` of a `ULong` id: `(int) (v ^ (v >>> 32))`.
pub fn long_hash(v: u64) -> i32 {
    (v ^ (v >> 32)) as u32 as i32
}

/// `HashMap.hash(key)`.
fn spread(h: i32) -> u32 {
    let h = h as u32;
    h ^ (h >> 16)
}

/// The table size after `n` distinct insertions: `put` grows once the size passes the
/// threshold, `computeIfAbsent` only when it is already past it at the next insertion.
fn capacity_for(n: usize, compute_if_absent: bool) -> usize {
    let size = if compute_if_absent { n.saturating_sub(1) } else { n };
    let mut cap = 16usize;
    while size > cap * 3 / 4 {
        cap *= 2;
    }
    cap
}

fn order<T>(keys: Vec<(i32, T)>, compute_if_absent: bool) -> Vec<T> {
    let cap = capacity_for(keys.len(), compute_if_absent);
    let mut indexed: Vec<(usize, i64, T)> = keys
        .into_iter()
        .enumerate()
        .map(|(i, (h, t))| {
            let i = i as i64;
            ((spread(h) as usize) & (cap - 1), if compute_if_absent { -i } else { i }, t)
        })
        .collect();
    indexed.sort_by_key(|(bucket, i, _)| (*bucket, *i));
    indexed.into_iter().map(|(_, _, t)| t).collect()
}

/// Distinct keys (in insertion order, with their Java hash codes) as a `HashMap` filled by
/// `put` iterates them.
pub fn iteration_order<T>(keys: Vec<(i32, T)>) -> Vec<T> {
    order(keys, false)
}

/// The same for a map filled by `computeIfAbsent`, as `Collectors.groupingBy` fills it.
pub fn grouping_order<T>(keys: Vec<(i32, T)>) -> Vec<T> {
    order(keys, true)
}

/// `new HashMap<>(source)` iterated, given the source's own iteration order: the copy is sized
/// for the source up front (`tableSizeFor(ceil(n / 0.75))`, JDK 19 and later) and filled in the
/// source's order, so it never grows and keeps that order within a bucket.
pub fn copy_order<T>(keys_in_source_order: Vec<(i32, T)>) -> Vec<T> {
    let n = keys_in_source_order.len();
    let want = (n as f64 / 0.75).ceil() as usize;
    let cap = want.max(1).next_power_of_two();
    let mut indexed: Vec<(usize, usize, T)> = keys_in_source_order
        .into_iter()
        .enumerate()
        .map(|(i, (h, t))| ((spread(h) as usize) & (cap - 1), i, t))
        .collect();
    indexed.sort_by_key(|(bucket, i, _)| (*bucket, *i));
    indexed.into_iter().map(|(_, _, t)| t).collect()
}

/// `new HashSet<>(ids)` iterated: duplicates dropped (first insertion wins), then hash order.
pub fn hash_set_order_u64(ids: impl IntoIterator<Item = u64>) -> Vec<u64> {
    let mut seen = std::collections::HashSet::new();
    let distinct: Vec<(i32, u64)> = ids.into_iter().filter(|id| seen.insert(*id)).map(|id| (long_hash(id), id)).collect();
    iteration_order(distinct)
}

/// String keys of a `HashMap` iterated.
pub fn hash_map_order_str<'a>(keys: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let mut seen = std::collections::HashSet::new();
    let distinct: Vec<(i32, &str)> =
        keys.into_iter().filter(|k| seen.insert(*k)).map(|k| (string_hash_code(k), k)).collect();
    iteration_order(distinct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_claim_order_matches_a_java_token() {
        // The payload of a token minted by the Java service on 2026-10-15.
        let inserted = ["userId", "hostName", "port", "loggedInClientId", "loggedInClientCode", "appCode", "oneTime"];
        assert_eq!(
            hash_map_order_str(inserted),
            vec!["hostName", "port", "loggedInClientId", "loggedInClientCode", "appCode", "oneTime", "userId"]
        );
    }

    #[test]
    fn small_ids_iterate_by_bucket() {
        // 17 and 1 share bucket 1 in a 16 table; insertion order decides within it.
        assert_eq!(hash_set_order_u64([17, 3, 1, 2]), vec![17, 1, 2, 3]);
        // Thirteen keys grow the table to 32, so 17 and 1 separate.
        let ids: Vec<u64> = (1..=13).chain([17]).collect();
        let order = hash_set_order_u64(ids);
        assert_eq!(order.first(), Some(&1));
        assert_eq!(order.last(), Some(&17));
    }

    #[test]
    fn grouping_by_puts_later_keys_first_in_a_bucket() {
        // Role ids of profile 1 on the local stack: 118 of them, the last 327 (= 256 + 71). The
        // Java service lists 327 just before 71.
        let mut ids: Vec<u64> = vec![1, 2, 4, 5, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 25, 26, 33];
        ids.extend([64, 65, 66, 67, 69, 70, 71, 72]);
        ids.extend((73..=160).take(88));
        ids.push(327);
        let ids: Vec<u64> = ids.into_iter().take(117).chain([327]).collect();
        let order = grouping_order(ids.iter().map(|i| (long_hash(*i), *i)).collect());
        let at = |v: u64| order.iter().position(|x| *x == v).unwrap();
        assert_eq!(at(327) + 1, at(71));
        // 13 keys: put grows to 32 buckets, computeIfAbsent stays at 16.
        let ids = [1u64, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7];
        let keys: Vec<(i32, u64)> = ids.iter().map(|i| (long_hash(*i), *i)).collect();
        assert_eq!(grouping_order(keys.clone()), vec![17, 1, 18, 2, 19, 3, 20, 4, 21, 5, 22, 6, 7]);
        assert_eq!(iteration_order(keys), vec![1, 2, 3, 4, 5, 6, 7, 17, 18, 19, 20, 21, 22]);
    }

    #[test]
    fn a_copy_is_sized_for_its_source() {
        // Three keys: the copy has 4 buckets where the source had 16, so 1 and 5 now share one.
        let src: Vec<(i32, u64)> = [5u64, 1, 2].iter().map(|i| (long_hash(*i), *i)).collect();
        let source_order = iteration_order(src);
        assert_eq!(source_order, vec![1, 2, 5]);
        let copied = copy_order(source_order.iter().map(|i| (long_hash(*i), *i)).collect());
        assert_eq!(copied, vec![1, 5, 2]);
        assert!(copy_order::<u64>(vec![]).is_empty());
    }

    #[test]
    fn ulong_hash_is_long_hash() {
        assert_eq!(long_hash(142), 142);
        assert_eq!(long_hash(1u64 << 32), 1);
    }
}
