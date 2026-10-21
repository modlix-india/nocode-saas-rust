# platform: deliberate differences from the Java commons

What every unit inherits from `platform` and does differently from the Java services.

## Local caches: bounded per family, by size or by count (2026-10-21)

Java (`AbstractBaseConfiguration`) keeps one Caffeine cache per cache NAME, each capped at
10,000 entries and expiring an hour after write. Names carry the app, page or client
(`PageCache_<app>_<page>`, `profileAuthsById_42`), so the total has no bound: it grows with every
page and client served. On dev, ui-engine was OOM-killed at its 1 GB limit (2026-10-21 12:06 UTC)
and stage ui-engine held 1.5 GB.

`platform::cache` keeps one Moka cache per FAMILY (one value type), keyed by the full cache name
and the key, bounded as a whole:

- **Weighed families** (`CacheService::family_weighed`): resolved definitions, app properties,
  fillers, index pages, JS files, list pages, parsed functions and schemas. Bounded by estimated
  size, `[redis] cache_budget_mb` per family (default 128).
- **Other families** (`CacheService::family`): tokens, flags, ids and small records, whose size
  cannot be seen behind an `Arc`. Bounded by count, `[redis] cache_max_entries` per family
  (default 20,000).
- Values still expire `[redis] cache_ttl_secs` (default 3600) after they were loaded.

Eviction messages behave as before: `<prefix>-<name>:<key>` drops that key, `<prefix>-<name>:*`
drops every entry of that name and no other (an invalidation predicate on the name; Moka never
returns an entry a predicate matches, even before its maintenance removes it). A name stays
listed in `getCacheNames` / `getCacheStats` once it has held a value, with 0 entries after it is
cleared, as an emptied Caffeine cache is.

The difference callers can see: under memory pressure an entry may be dropped earlier than Java
would drop it (the family is full), so a hot page can be read again from Mongo. The `cache_*`
metrics (deploy/METRICS.md) show when a family runs at its limit.

## Allocator: mimalloc (2026-10-21)

Every unit allocates through mimalloc (`#[global_allocator]` in `platform/src/lib.rs`). With
glibc's malloc under Tokio's worker threads, freed memory stayed in per-thread arenas and resident
memory stayed near its peak. kirun's benchmark (nocode-kirun/kirun-rust/bench) has mimalloc 30 to
40% faster than the system allocator on every workload, with 40% less peak memory.
