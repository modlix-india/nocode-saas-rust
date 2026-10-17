# Deliberate differences from Java

Each entry says what Java does, what this crate does instead, and why. Anything not listed
here behaves as the Java service does, statuses and messages included.

## Error bodies: coded, plain-language messages (2026-10-17)

Every refusal the library makes carries a stable code and a message written for the person
reading it, from the catalogue in `messages/en.toml` (codes `DEF.*`, see `src/catalogue.rs`) and
the platform's (`COMMON.*`). The status codes are Java's, unchanged; so is the 404-vs-403 split.

| | Java | Rust |
|---|---|---|
| `message` | the bundle text (`Page with id x not found`) | the catalogue text in the request's language (`We couldn't find the page with id x.`) |
| `debugMessage` | the same text | Java's text under its key, `[object_not_found] Page with id x not found`; Spring's text for Spring's 400s; the cause for a 500 |
| added fields | none | `code`, `action`, `params` (the values, as words), `locale` |
| an anonymous caller refused a change, a draft, a list or a publish | the refusal naming the type or app (`Permission/Role Page is required...`) | `DEF.SIGN_IN_REQUIRED`, "Please sign in to continue." (same status) |
| Spring's 400s | "Please try again. A server error - <id>" | `COMMON.PARAM_MISSING`, `PARAM_INVALID`, `BODY_MISSING`, `BODY_UNREADABLE`, `FIELD_MISSING` or `DEF.HEADER_MISSING`, naming the parameter or header when known; still 400 |
| 500s | "Please try again. A server error - <id>" | `COMMON.INTERNAL_ERROR`, "Something went wrong on our side. Error id <id>: give it to support." |
| a credential security refuses without a message | empty 401 or 403 | `COMMON.SIGNED_OUT`, same status |
| security's refusal with a body | its message | its coded error as it came (Rust security), else its message |

- A unit adds its own namespace for its own keys (`Messages::add_namespace("UI")`); a key no
  namespace codes answers Java's text as before.
- publishAll's per-object `error` keeps Java's text (`messages::error_message`).
- One key, two meanings: `unable_to_delete` answers `DEF.UNABLE_TO_DELETE` when the caller may
  not delete (404) and `DEF.DELETE_BLOCKED_BY_OVERRIDES` when other organisations' customised
  copies stand on the object (403); Java says the same text for both.

## Security fixes

1. **`create` never takes an id from the body.**
   - Java: `AbstractMongoDataService.create` calls `repo.save(entity)`. When the request body
     carries an `id`, Spring Data upserts by that id. The access check covers only the codes in
     the body. So a caller allowed to create in its own client could replace any document in the
     collection, another tenant's included, by naming its id.
   - Rust: `create` clears the id and always inserts. No legitimate caller sends one: forks and
     transport imports already null it.
2. **The cached list checks access first.**
   - Java: `readPageFilterLRO` serves the `_READ_PAGE` cache before its access check, which runs
     only on a miss. A caller with the same client code got the cached list without the
     authentication and app-access checks, an anonymous caller on that client's host included.
   - Rust: the check runs before the cache is consulted.
3. **Version history is scoped to the caller's chain.**
   - Java: `AbstractVersionService.accessCheck` asks whether the caller's own inheritance chain
     contains the caller, which it always does. So any client with the type's `_READ` authority
     and read access to the app could read any other client's version rows, which hold whole
     objects.
   - Rust: the chain must also contain the version's client, the rule the object reads use.
4. **`POST /versions/{id}/query` checks access.**
   - Java: `readPagePerObjectId` has no access check at all, so anyone could page through any
     object's history by id.
   - Rust: it answers an empty page unless the caller passes the version check above on that
     object's history.

## Behaviour fixes

5. **`clientOnly` on the list works.**
   - Java: `readPageFilterLRO` leaves `clientOnly` out of the parameters it ignores. It becomes a
     regex filter on a `clientOnly` field no document has, so any `clientOnly` value returned an
     empty page. The `_READ_PAGE` cache key also lacks `clientOnly`.
   - Rust: `clientOnly` is never a filter and is part of the cache key.
6. **`deleteEverything` evicts every name.**
   - Java: the per-name `evictAll` calls sit inside `.map(...)` and are never subscribed. With
     Redis the local clear and the publish still happen (they run eagerly) but the L2 `DEL`
     never does; without Redis nothing is evicted. The draft surface's caches are never evicted.
   - Rust: evicts `<Cache>_<app>_<name>` and its `_DRAFT` for every name, fully.
7. **Filler read cache.**
   - Java: the `FILLER_READ` cache has no surface in its name or key. A draft-surface read could
     answer the live surface and the other way round, and `evictDraft` does not clear it.
   - Rust: the draft surface's entry has its own key (`<client>:draft`), and `evictDraft` clears
     the cache.
   - Java keys the `update` eviction on the body's `appCode`; Rust uses the stored one.

## Ordering and determinism

8. **Order.** Where Java's `flatMap` runs things concurrently and its output order is
   unspecified, Rust runs them in order and the output is deterministic. This applies to:
   - the eager list's `data` reads;
   - the objects inside one dependency wave of a transport import;
   - the per-service reads of an export;
   - the entries of an export zip.

   Waves are still applied in order, and so are types (in service order).
9. **Key order.** `cleanupOlderThan` answers `{transportsRemoved, versionsRemoved}` in that
   order; Java's `Map.of` has none.

## Small edges

10. **`sort: null` in a version query** means the default sort. Java throws a
    `NullPointerException` (500).
11. **Timestamps.** A document re-saved by Rust keeps the stored dates to the millisecond. A date
    that only arrived as epoch seconds in a body is stored at whole seconds, as Jackson read it.
12. **Spring's own 400s** (an unreadable body, a missing or unconvertible parameter, a missing
    header or multipart part) keep Java's status and Spring's text as the debug message
    (`controller::spring_refusal`, rendered by `controller::error_response`), with the code that
    names the problem (see Error bodies above). The debug text is Spring's where it is known;
    for a missing forwarded header it does not name the header.

## Kept on purpose (Java behaviour, noted here so nobody "fixes" it by accident)

- **`IS_NULL` (not negated)** renders as `{f: {$exists: false, $eq: null}, $or: [...]}`, so it
  matches only documents where the field is absent, not where it is `null`. A negated `BETWEEN`
  matches nothing.
- **Version snapshots of a derived object hold the override delta**, because `extractDifference`
  mutates the entity before it is snapshotted. Publish reconciliation still diffs that snapshot
  against applied content (see the report).
- **`delete` evicts only the deleting client's key** of the definition caches.
- **The `SortDeserializer`'s `ignoreCase` never takes effect.**
- **A version type missing from `mapAuthName`** (ui: `URIPATH`, `FILLER`, `TRANSPORT`; core:
  `NOTIFICATION`, `WORKFLOW`, `FILLER`, `TRANSPORT`) checks `Authorities.null_READ` and is always
  refused.
