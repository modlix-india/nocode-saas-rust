//! The iteration order of a `java.util.HashMap`, which is the key order of every map the Java
//! services send: their copy constructors (`CloneUtil`) rebuild each map as a `HashMap` before
//! Jackson writes it.
//!
//! A `HashMap` iterates bucket by bucket, and within a bucket in insertion order (a resize
//! splits a bucket in two without reordering it). The bucket of a key is
//! `(h ^ (h >>> 16)) & (capacity - 1)` with `h = key.hashCode()`. So the order is a stable sort
//! of the insertion order by bucket, once the capacity is known, and the capacity depends on
//! how the map was built:
//! - by successive puts (`new HashMap<>()`, `Collectors.toMap`, Reactor's `collectMap`): 16,
//!   doubled whenever the size passes three quarters of it;
//! - by the copy constructor `new HashMap<>(other)`: `tableSizeFor(ceil(size / 0.75))`.
//!
//! Not modelled: a bucket holding 8 or more keys becomes a tree on large tables, which orders
//! that one bucket differently. Real definitions never put eight keys in one bucket.

use platform::java::string_hash_code;

use crate::json::{JMap, JValue};

/// Capacity after `n` puts into a fresh `HashMap`.
pub fn capacity_by_puts(n: usize) -> usize {
    let mut cap = 16usize;
    while n > cap * 3 / 4 {
        cap *= 2;
    }
    cap
}

/// Capacity of `new HashMap<>(m)` for a source of size `n` (JDK 19+ `putMapEntries`).
pub fn capacity_by_copy(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let t = (n as f64 / 0.75).ceil() as usize;
    t.next_power_of_two().max(1)
}

pub fn bucket(key: &str, capacity: usize) -> usize {
    let h = string_hash_code(key) as u32;
    ((h ^ (h >> 16)) as usize) & (capacity - 1)
}

/// Reorders `map` (whose current order is taken as the insertion order) into the iteration
/// order of a `HashMap` of `capacity`.
pub fn order(map: JMap, capacity: usize) -> JMap {
    let mut entries: Vec<(usize, String, JValue)> =
        map.into_iter().map(|(k, v)| (bucket(&k, capacity), k, v)).collect();
    entries.sort_by_key(|e| e.0);
    entries.into_iter().map(|(_, k, v)| (k, v)).collect()
}

/// A `HashMap` filled by successive puts in the current order.
pub fn by_puts(map: JMap) -> JMap {
    let cap = capacity_by_puts(map.len());
    order(map, cap)
}

/// `new HashMap<>(map)`.
pub fn by_copy(map: JMap) -> JMap {
    let cap = capacity_by_copy(map.len());
    order(map, cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(m: &JMap) -> Vec<&str> {
        m.keys().map(String::as_str).collect()
    }

    #[test]
    fn matches_the_java_order_seen_on_the_wire() {
        // An application's properties as stored, and as the Java ui sent them (2026-10-15).
        let stored: JMap = ["defaultPage", "notFoundPage", "links", "styles", "themes", "fontPacks"]
            .iter()
            .map(|k| (k.to_string(), JValue::Null))
            .collect();
        let m = by_puts(stored);
        assert_eq!(keys(&m), ["fontPacks", "themes", "defaultPage", "links", "styles", "notFoundPage"]);
    }

    #[test]
    fn capacities() {
        assert_eq!(capacity_by_puts(0), 16);
        assert_eq!(capacity_by_puts(12), 16);
        assert_eq!(capacity_by_puts(13), 32);
        assert_eq!(capacity_by_puts(25), 64);
        assert_eq!(capacity_by_copy(3), 4);
        assert_eq!(capacity_by_copy(6), 8);
        assert_eq!(capacity_by_copy(12), 16);
        assert_eq!(capacity_by_copy(13), 32);
    }

    #[test]
    fn copy_constructor_capacity_orders_small_maps_differently() {
        // Three keys: 4 buckets by copy, 16 by puts.
        let m: JMap = ["c", "b", "a"].iter().map(|k| (k.to_string(), JValue::Null)).collect();
        let copied = by_copy(m.clone());
        assert_eq!(keys(&copied), ["a", "b", "c"]);
        assert_eq!(capacity_by_copy(0), 1);
        assert_eq!(capacity_by_copy(1), 2);
        assert_eq!(bucket("a", 16), 1);
        let ordered = order(m, 2);
        assert_eq!(ordered.len(), 3);
    }

}
