# appdata: differences from the Java app-data engines

What this crate is measured against: `MongoAppDataService`, `MySQLAppDataService` and the
`mysql/` package in `nocode-saas/commons-core` (the engines below `AppDataService`).

- `tests/java_oracle.rs` compares the Rust builders with what the real Java builders produce
  for the same inputs (fixtures written by `tools/parity_appdata/oracle/run.sh`): MySQL filters,
  Mongo filters, MySQL aggregate page/count SQL, Mongo `$group` / `$project` stages, and the
  JSON of the drift report, drift repair and migration outcome records.
- `tools/parity_appdata/parity_appdata.rs` runs the same reads through Java
  (`/api/core/data/...` on 8005) and through the engines on real local data, read only.
- `tests/java_*.rs` (no database) and `tests/live_*.rs` (local MySQL / MongoDB, scratch
  `RUSTTEST_*` databases, `--ignored --test-threads=1`) port the Java engine tests of
  commons-core and core with their inputs and expectations; each module is named after
  the Java class it ports.

Every compared case is the same, or is one of the entries below. The parity tool prints
`EXPECT ... (DIFFERENCES.md: <entry>)` for the ones it can see.

## Fixed, not kept

- **Mongo COUNT_DISTINCT.** Java's `projectStage` builds the `$filter` condition with
  `List.of("$$this", null)`, and `List.of` refuses a null, so every Mongo aggregate with a
  `COUNT_DISTINCT` that passes validation is a 500 (`NullPointerException`). The Rust stage is
  the one the Java code means: `{"$size": {"$filter": {"input": "$<alias>", "cond": {"$ne":
  ["$$this", null]}}}}`, the number of distinct non-null values. Seen in parity on
  `appbuilder/SYSTEM/Doc` and `sitezump/SYSTEM/templateStorage`; oracle case `a2`.
- **Decimal128 that is not a finite number.** A stored `NaN`, `Infinity`, `-Infinity` or
  negative zero Decimal128 makes Java's `MongoValueCodec` (`bigDecimalValue()`) throw, so the
  read is a 500. Rust reads it as its text (`"NaN"`, `"Infinity"`, `"-Infinity"`, `"-0"`).
  The engine never writes one; only a document written some other way can hold it.
- **Sort on a JSON path that is not a path (MySQL).** Java's `order()` resolves each sort
  key outside any `catch`, so a malformed path (`address.c'ty`) escapes `rows()` as an
  `UnsupportedFilterException` and the read is a 500. Rust maps it the way the filter
  path does: 400 `UNSUPPORTED_CONDITION`, the same answer as the same path in a filter.

## Port gaps the ported Java tests found (fixed)

- **Referenced schemas on the draft surface (MySQL).** Java resolves a storage's `ref`s
  through `CoreSchemaService.getSchemaRepository` under the reactor context's draft flag,
  so a client's own schema draft shapes that client's draft tables and nothing else
  (`MySQLDraftPublishIntegrationTest`: `draftSaveMovesOnlyDraftTables`,
  `discardRestoresDraftTables`, `publishMovesLiveTables`). The Rust hook had no surface,
  so every table resolved the live schema and a schema draft never reached a draft table.
  `SchemaRepositories::for_surface(app, client, draft)` now carries the surface and the
  MySQL engine passes it on every resolve (the caller's `Ctx`, or the tenant database's
  `_draft` suffix in reconcile and drift). Its default falls back to `for_app`, so an
  implementation that has not added it behaves as before: `crates/core`'s `StorageDefs`
  still implements only `for_app`, and schema drafts reach draft tables there once it
  implements `for_surface` (the client's own drafted schema first on the draft surface).

## Different on purpose

- **List or map compared in a MySQL filter.** Java's `MySQLFilterBuilder` renders the
  condition and the R2DBC driver fails when it binds the list or map (a 500 from the read).
  The Rust filter builder refuses it while building (`FilterError::Unbindable`, also a 500),
  so no SQL is sent. Same status; `tests/java_oracle.rs` checks every such case is one Java
  could not bind.
- **Binary-flagged columns holding text (MySQL).** sqlx calls a column binary from MySQL's
  BINARY flag, which MySQL also sets for a `_bin` collation and for `JSON_UNQUOTE` results.
  A binary-typed value that is valid UTF-8 is read as a string, as R2DBC (which looks at the
  charset) reads those columns; other bytes are base64, as Jackson writes a `byte[]`. The
  catch: a real `BINARY` / `VARBINARY` / `BLOB` column whose bytes happen to be valid UTF-8
  comes back as text where Java would base64 it. The engine never creates such columns; only
  a customer-supplied table can have one.
- **readAuth of a joined or sub-queried storage.** Java evaluates the expression with
  KIRun's `ExpressionEvaluator` (`SecurityContextUtil.hasAuthority`). The engines call
  `Hooks::has_authority`, which uses `Hooks.authority` when the caller plugs in the full
  evaluator, and otherwise `Ctx::has_authority`: blank allows, `or` of `and` of authority
  names, `not` before a name. The readAuth values in local `core.storage` are single names
  and `or` lists, which it covers; nested parentheses, and anything else KIRun accepts, it
  does not. One local value is comma-separated names; the fallback reads that as one name
  (never granted), and what KIRun makes of it was not checked. Whoever wires the HTTP layer
  should plug in the KIRun evaluator (`crates/core` has `authorities::has_authority`).
- **Copy to draft on Mongo.** Java upserts with `bulkWrite` of `ReplaceOneModel` in batches
  of 500; Rust reads in batches of 500 and upserts one document per call (`replace_one`
  with upsert). The result and the count are the same; it is more round trips. The Rust
  driver's only bulk write is the client-level one, which needs MongoDB 8.
- **Copy one storage to draft on MySQL: key checks off (QA-0483, 2026-10-21).** Java's
  `copyLiveToDraft(storage, replace)` ran its `DELETE` and `INSERT ... SELECT` with foreign
  keys checked, so copying a storage whose rows point at another storage failed with MySQL 1452
  until that storage had been copied first, and replacing a storage that other draft rows point at
  failed on a RESTRICT key (1451). Rust runs both on one connection with
  `FOREIGN_KEY_CHECKS = 0`, as the whole-app `copyAppToDraft` already does. The copied rows may
  point at draft rows that are not there yet; copying the referenced storage later fills them in.
- **Migration claim node id.** Both are `<host>:<time>`. Java's time is the JVM start time;
  Rust's is the first time the process asks. Either is unique to one process, which is all
  recovery uses it for.
- **MySQL session time zone.** sqlx sets `time_zone = '+00:00'` on every connection (made
  explicit in `db::connect_options`); Java's R2DBC session keeps the server's zone. The
  engine's columns are `DATETIME` and every time it writes is computed in UTC in code, so
  nothing it stores or reads changes. Only a customer table with a `TIMESTAMP` column, or a
  default of `NOW()`, would read in UTC here.
- **Condition JSON.** A filter condition's `valueField` / `toValueField` is also accepted as
  `isValueField` / `isToValueField`. In Java the Jackson path reads the first spelling and the
  Gson path (KIRun functions) the second; both reach the engines, so this parser takes both.
- **Rows streamed vs collected.** `read_page_rows` (Java `readPageAsFlux`) returns the rows
  as a `Vec`, not a stream.
- **Resolved schemas are not cached.** `Hooks::resolved_schema` resolves a storage's `$ref`s
  on every call; Java's `StorageService.getResolvedSchema` caches it per storage and draft
  flag and evicts it when the storage changes. Same result, more lookups. The cache (and its
  eviction) belongs with whoever ports `StorageService`; the `SchemaRepositories` hook is
  where it plugs in.
- **MySQL pools.** sqlx pools are created lazily and test a connection before handing it out
  (`test_before_acquire`). Java uses r2dbc-pool. Not visible in any answer.

## Found by the ported tests' gap pass, kept

Edge paths no ported Java test reaches; each was checked against the Java code (most on a
JVM) and is recorded rather than changed.

- **Mongo connection with no url.** Java's `getMongoClient` throws
  `CONNECTION_DETAILS_MISSING` (404) from `estimatedRowCount`, `dropDraftStorage` and
  `dropDraftDatabase`; Rust answers 0 / `false`. Failing instead needs
  `estimated_row_count` to return a result, a signature `crates/core` uses.
- **Decimal128 at the edges (Mongo).** Java's `Decimal128` constructor takes any
  coefficient that fits 113 bits; Rust refuses a 35-digit one between 10^34 and 2^113, and
  words the refusal of one over 38 digits differently. For a field declared DECIMAL128,
  Java's codec fails some extreme values with an `AssertionError` (a 500, e.g.
  `10000000000000000000000000000000000E+6111`); Rust stores them as text.
- **Model JSON coercions.** The `from_value` parsers refuse what Jackson coerces: an enum
  given by its index (`"function": 5`), a fractional `page` / `size`, a `condition` that is
  not an object (Java: no condition). `"count": 1` reads as no count (Java: true) and
  `"count": "yes"` as no count (Java: an error). A malformed `groupBy` element or a
  non-empty `fieldExpr` array is skipped, and an unknown enum name (bsonType, column type,
  delete constraint, direction, schema type) reads as absent, where Java fails the parse.
  No caller sends these shapes.
- **Java text of a few values.** `java_double` writes subnormals with the shortest digits
  (`5.0E-324`, Java `4.9E-324`); `java_string` of a `LocalDateTime` / `LocalTime` keeps
  `:00` seconds that Java's `toString` drops, and of a `Date` gives the millis rather
  than `Date.toString()`; `LocalTime.parse` accepts `10:00:00.` and Rust does not. The
  codecs turn these values into text before any of it is reached.

## Switches that exist only here

- `migration::sweep_schemas` sweeps the schemas it is given; Java's sweeper always takes
  every schema on its server, and `migration::sweep` still does. It exists so tests on
  the shared local server finish only their own scratch schemas.

- `MongoEngineConfig.skip_index_management` and `MySqlEngineConfig.skip_provisioning`, both
  `false` by default (Java's behaviour). `true` stops the engine from creating or altering
  indexes / databases / tables / foreign keys, so a tool can read real tenants without
  writing to them. The parity tool sets both.
- `engine::Ctx` carries what Java takes from the reactive security and reactor contexts
  (url client code, user id, authorities, the draft flag); `engine::Hooks` carries what the
  engines took from Spring services (write validator, schema repository, per-tenant storage
  lookup, authority evaluator). `PassThrough` is a validator that accepts everything; the
  real one belongs to the policy layer.

## Not part of this crate

- The `AppDataService` policy layer: auth gates, triggers, relation filling, events, the
  write validator itself. The engines take a `WriteValidator` hook instead.
- `lookup::MongoDefinitions` reads `storage` / `connection` / `schema` documents from the
  core database as stored, with no override or inheritance merge and no cache. It is for
  tooling and tests (the parity tool uses it); a service should resolve definitions through
  the overridable service the way Java's `StorageService` does.
- The HTTP layer (`AppDataController`).

## Same on purpose (quirks kept)

- Mongo honours `isAppLevel` (the url client's database) on every operation; MySQL honours
  it only when dropping a draft table, exactly as Java does.
- A connection with no `connectionSubType` that is not null is a 500, as Java's switch on a
  null enum is a `NullPointerException`; no connection means Mongo.
- A Mongo filter with a null operator is a 500, as in Java.
- An update (PUT) of a MySQL row that does not exist answers empty (`AppDataError::Empty`),
  as Java's `update` completes empty.
- A Spring `Page` written by Jackson with `NON_EMPTY`: an empty page has no `content` key.

## Error codes (2026-10-17)

Every message the engines raise (`AppDataError::Message`) carries the core catalogue's code
(`CORE.*`, `crates/core/messages/en.toml`, which this crate registers too) with its values named:
a missing row is `CORE.ROW_NOT_FOUND`, a missing version `CORE.VERSION_NOT_FOUND`, a data
connection without its address `CORE.DATA_CONNECTION_INCOMPLETE`, the rest the code named after
their Java key. Java's text is unchanged in `message()` and goes to the answer's `debugMessage`;
the plain text and next step come from the code (see core's DIFFERENCES.md, "Error bodies").
