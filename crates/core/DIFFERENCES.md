# core-exec: deliberate and known differences from the Java core

Each entry has the tag `tools/parity_core_exec.py` or `tools/parity_core_data.py` (storage,
step 2) reports for it. `D` entries are differences
of this unit (kept, fixed, or not ported yet). `K` entries came from the `kirun` crate behaving
like kirun-js where the Java core runs kirun-java. All six were resolved on 2026-10-17 in the
`kirun` crate itself (`nocode-kirun/kirun-rust`, its `DESIGN.md` "Where kirun-rust answers as
kirun-java"): the owner decided stored server functions must return what they return today, so
kirun-rust now answers as kirun-java 4.9.2 in those areas. The crate change is in the
nocode-kirun working tree, not released (crate version unchanged); core-exec builds against it
by path.

## Error bodies: coded, plain-language messages (every core unit, 2026-10-17)

Every error core-exec, core-editor, core-events and core-scheduler answer (and the appdata and
connections libraries raise) carries a stable code and a message written for the person reading
it, from the catalogue in `messages/en.toml` (codes `CORE.*`: one per key of Java's core bundle,
plus the literal texts Java raises) and the platform's (`COMMON.*`). appdata and connections
register the same file. The status codes are Java's, unchanged; the Java text travels inside the
error unchanged (KIRun, the event run log and the scheduler parity read Java's words).

| | Java | core units |
|---|---|---|
| `message` | the bundle or literal text (`Unable to read data from storage leads`) | the catalogue text in the request's language (`You can't view the data in leads: your account does not have the permission this storage needs for reading.`) |
| `debugMessage` | the same text, or the cause | Java's text under its key (`[forbidden_read_storage] Unable to read data from storage leads`), Java's literal text, or the cause, as Java sends it |
| added fields | none | `code`, `action` (when there is a next step), `params`, `locale` |
| not signed in on a protected path | empty 401 | 401 with `COMMON.SIGNED_OUT` (a token or password was sent and refused) or `COMMON.SIGN_IN_REQUIRED` |
| `@PreAuthorize` refusal (event runs, the schedule routes) | 403 `text/plain` "Access Denied" | 403 JSON `COMMON.PERMISSION_REQUIRED`, naming the permission |
| Spring's 400s (missing header or parameter, unconvertible value, missing or unreadable body) | "Please try again. A server error - <id>" | `COMMON.HEADER_MISSING`, `PARAM_MISSING`, `PARAM_INVALID`, `BODY_MISSING`, `BODY_UNREADABLE`; still 400, Spring's text in `debugMessage` |
| unmapped path, wrong method | "Please try again. A server error - <id>" (404, 405) | `COMMON.NOT_FOUND`, `COMMON.METHOD_NOT_ALLOWED` |
| 500s | "Please try again. A server error - <id>" | `COMMON.INTERNAL_ERROR` ("Something went wrong on our side. Error id <id>: give it to support.") |
| a server function failing inside a step | 500 "Please try again. A server error - <id>", KIRun's chain in `debugMessage` | 500 `CORE.FUNCTION_STEP_FAILED`: "Step <step> (<step's function>) in <function> failed: <reason>", the reason being the runtime's own (the parameter whose value did not fit, the expression that failed); `debugMessage` is KIRun's chain followed by the steps, innermost first (`at step <step> (<function>) of <definition>`, no arguments). `CORE.FUNCTION_FAILED` when no step accounts for it. A refusal or a missing object a function raises comes up with its own code, as Java lets it through |
| a refusal from a Rust security unit (core's caller, the caller-security functions, Feign calls) | security's status and message | passed on as it came: security's code, values, message, action and `debugMessage`, with its status (`platform::error::Coded::relay`); the text core carries inside is security's Java text |

- An anonymous caller refused by a storage's permissions is only asked to sign in
  (`You can't view this data without signing in.`): the storage is not named.
- Errors core-editor raises through the definition library (`crates/overridable`) carry its
  `DEF.*` codes; core's own keys (storage schemas, workflows) fall back to `CORE.*`.
- The parity scripts compare errors by status and code (`tools/error_parity.py`): the code must
  stand for Java's text and Rust's answer, put back into Java's shape, must match everything
  else. Such cases read `EXPECTED coded` (or keep their rule's tag, with the code noted).

## D: this unit

- **D1 number representation** (`D1-number-repr`). Mostly gone since 2026-10-17: kirun-rust's
  operators and `System.Math.*` keep kirun-java's number types (`Add(1.0, 2.0)` is `3.0`,
  `Floor(5)` is `5.0`, `int + int` wraps at 32 bits, `Round` gives a long). Left: a POST body
  number keeps its text in Java (Gson's `LazilyParsedNumber`, `1.50` echoes as `1.50`), here it
  is a parsed double (`1.5`); and kirun-java reads a decimal written in JSON text as a `float`
  (`0.1` is `0.10000000149011612` once widened), where kirun-rust holds a double, so arithmetic or
  `System.Math` on such decimals can differ in the trailing digits (`0.1 * 3`, `Sine(0.1)`).
  The parity runs of 2026-10-17 show no `D1` case.
- **D2 KIRun error wording** (`D2_kirun_error_text`). Both answer 500 with
  `Please try again. A server error - <id>`; the `debugMessage` is the runtime's message. Since
  2026-10-17 kirun-rust writes kirun-java's sentences (the schema path repeated,
  `value - value - ...`; `"abc" is not a Double`; enum lists as JSON; Java's NullPointerException
  texts). Left: the type list in `[Expected: ...]` (kirun-java prints a `HashSet` in hash order),
  the order of several plan messages, and `System.Math.Add` naming its parameter (D4). The other
  `D2` cases are not kirun's: Mongo ObjectId and filter-operator refusals, and definitions Java
  cannot read (D7).
- **D3 every core function is ported** (step 3). `CoreFunctions` registers all 72
  `CoreServices.*` functions of `CoreFunctionRepository`, in its order. The signatures of the 53
  added in step 3 are Java's own `repositoryFind` JSON, kept in
  `functions/java_signatures.json` and read back into kirun's model (a test checks each reads
  back to the JSON); a signature change in Java needs that file re-captured. One parameter in
  it is Rust only: `CoreServices.Email.SendEmail`'s `attachments` (see the connections crate's
  DIFFERENCES.md, item 25). Seven Rust-only
  `CoreServices.Platform.*` follow them (79 in all; see "Platform functions").
- **D4 KIRun built-ins follow kirun-js** (`D4_kirun_builtins`). The `System.*` functions and
  schemas are kirun-rust's: the set listed with `includeKIRunRepos=true` differs, signatures
  carry `parameterName` where kirun-java's have none (so a refused `System.Math.Add` value reads
  `...Add's parameter value [Expected: ...]` where Java writes `...Add [Expected: ...]`). Since
  2026-10-17 `System.Math.Add` with no values raises no event (Java answers `[]`, so does
  core-exec), as kirun-java.
- **D5 schemas with enums or defaults** (`D5_java_jackson_jsonprimitive`). Java's
  `schemas/repositoryFind` answers 500 (`JSON encoding error`) for any schema holding `enums`,
  `defaultValue`, `examples` or `constant`: Jackson cannot write Gson's `JsonPrimitive`
  (`Primitive is neither a number nor a string`, `For input string: "KNOWN"`,
  `Not a JSON Array: 1`). That includes KIRun's own `System.Schema` with
  `includeKIRunRepos=true`. core-exec answers the schema. Fixed, not kept.
- **D7 definitions Java cannot read** (`D7_definition_java_cannot_read`). A stored definition
  that Gson refuses (`"type": ["EXPRESSION"]` where an enum is expected) or that has no `steps`
  fails in Java (500, also on `repositoryFind`); kirun-rust reads it and runs it. Found on
  appbuilder `MyApp.greet` and several step-less cxapp / kyc / crmai functions.
- **D8 repository order.** Java's `ReactiveHybridRepository.find` subscribes to every
  repository at once and takes the first that emits: KIRun and core (synchronous) always win,
  the app's Mongo read and entity-processor race. core-exec asks KIRun, core, the app (then its
  dependencies), entity-processor, in that order. Only a name defined in two of them can tell.
  `repositoryFilter` keeps every name (no de-duplication, as Java) but in source order, where
  Java's order is the core `HashMap` then completion order; the parity script compares lists
  as multisets.
- **D9 `grantedAuthorities` order** (`D9-granted-authority-order`). `GetAuthentication` /
  `GetUser` write the user's `HashSet<SimpleGrantedAuthority>` in `HashSet` order (bucket by
  `role.hashCode()`), which is reproduced; within one bucket Java's order comes from a parallel
  stream and can differ. Same set.
- **D10 lookup failures inside a run.** KIRun's `Repository::find` cannot report an error, so a
  Mongo or entity-processor failure while the runtime looks up a step's function is logged and
  reads as `function is not found`. Java fails with the underlying error. Top-level lookups
  (the function executed, `repositoryFind`) do report the error.
- **D11 schema `type` arrays.** Java writes a multi-type as a `HashSet<SchemaType>`, whose order
  follows the enum's identity hash (different per JVM run); core-exec keeps the stored order.
  The parity script compares them as sets.
- **D12 error bodies.** `stackTrace` is always empty (Java sends the server stack). A POST body
  that is not a JSON object fails with 500 either way, with different `debugMessage` text.
- **D13 query values.** A query parameter without `=` is an empty string here (Spring gives
  null and the conversion then fails with a NullPointerException). A DOUBLE parameter of
  `NaN` / `Infinity` becomes `null` (JSON has no such numbers). Hexadecimal floating literals
  (`0x1p3`) are refused (Java's `Double.valueOf` accepts them).
- **D14 parsed definitions are cached** by the resolved document's content id, so a cached
  definition is not re-parsed on every call. Java parses it on every lookup; no visible
  difference.

### Storage (step 2: `AppDataService`, `CoreServices.Storage.*`, the data routes)

- **D15 no `WWW-Authenticate` on a 401** (`D15_no_basic_challenge`). The data and spreadsheet
  routes answer an anonymous caller with a bare 401, as `ISecurityConfiguration` does since
  nocode-saas `aca9929dd` (`HttpStatusServerEntryPoint`). The Java build running locally
  predates it and still sends `WWW-Authenticate: Basic realm="Realm"`; the parity script
  compares status and body only.
- **D16 unknown errors' text** (`D16_unknown_error_text`). Where both answer an unknown error
  (500, or a framework 400 such as a body Jackson cannot read or a boolean Spring cannot
  convert), `message` is the same and only `debugMessage` differs: schema validation of a
  written row (kirun-rust's wording, see D2), a database refusal (sqlx's text where Java's is
  R2DBC's: an unknown column, a duplicate key, a value out of range), Spring's own exception
  text, a trigger named without a namespace.
- **D17 another service's refusal** (`D17_feign_debug_message`). Same status and message;
  Java's `debugMessage` is Feign's exception text (method, URL and the whole downstream body),
  core-exec's is the message.
- **D18 storage events** are published to the `events` exchange (`integrations::MqEvents`,
  `connections::mq`), with the draft marker and `xdebug`, as `EventCreationService` does. Fixed
  with it: an `includeContextAuthentication` event carries the `ContextAuthentication` as
  Jackson writes it (it was Gson's form).
- **D19 a `BigDecimal` in a row** reaches KIRun (storage function outputs, trigger arguments)
  as an exact integer when it is one, otherwise as its double: `12.50` is `12.5` (Gson writes
  `BigDecimal.toString()`). The data routes write it as Java does.
- **D20 dates Gson cannot write.** A `LocalTime` value (MySQL `TIME`) goes to KIRun as its ISO
  text; Java's Gson has no adapter for it and fails on Java 21. A JSON / JSONL download writes
  `LocalDateTime` as epoch seconds (core's adapters), where Java's plain `new Gson()` fails the
  same way.
- **D21 XLSX.** Written: the same zip entries with the same contents; the deflated bytes and
  entry times differ by zip implementation. Read: shared strings, inline strings, booleans,
  date-formatted numbers as `yyyy-MM-dd` and other numbers in POI's "General" form are read as
  the streaming reader shows them; a cell with a custom number format reads as its plain
  number (POI's `DataFormatter` would apply the format).
- **D22 relation ids of a row just created on Mongo.** The engine hands a created row's
  relation ObjectIds over as Jackson writes them (`{timestamp, date}`), which no longer holds
  the hex id Java collects with `toString()`; for an eager create the ids the row was written
  with are used for the lookup instead. Same answer as Java's; see NEEDS (appdata).
- **D23 triggers run one after another.** Java subscribes to a storage's triggers of one kind
  concurrently (`Flux.flatMap`); core-exec runs them in their declared order. The same unless
  two triggers depend on each other's timing.
- **D24 key order inside a row** is not compared by the parity script (JSON objects compare
  as maps); Java's Mongo `create` answers a re-read document while the KIRun path's order
  follows the engine's, so the position of `_id` can differ.
- **D25 `migrationStatus` JSON** is the `TenantProgress` record as Jackson writes records
  (`database`, `state` unless null, `statementIndex`, `total`, `attempt`, then `done`,
  `untouched`, `resumable`); not compared live, as no local MySQL storage has a journal entry
  the Java build reports.
- **Not run by the live parity:** `ClearDraft` and `CopyToDraft` act on every storage of an
  app's draft surface, not only the scratch ones, so they are covered by the unit tests
  (`storage::service`, `functions::storage`) instead of being run against a shared app.

### Step 3: the other core functions, the connections wiring

- **D26 publishing can be off.** With `mq.enabled = false`, or no broker configured
  (`mq.uri`, or `mq.host` with the user and password), events and notifications are logged and
  dropped, and `CreateEvent` / `SendNotification` / storage writes answer as if the broker had
  them. Java always has a broker. The local runs and the parity runs use this, so nothing
  reaches the local `events` / `notifications` exchanges.
- **D27 an empty answer inside a definition.** Where a Java function completes empty
  (`IsBeingManagedBy*` / `GetClient` with security answering nothing, `Chat` without a security
  context, a `GetClientUsersPage` page security does not answer), core-exec raises 404
  "Function with id <that function> not found". On a direct execute that is Java's answer; inside
  a definition Java's run ends empty and the 404 names the definition instead.
- **D28 security ids are `u64`.** An id argument beyond `u64` is a 400 "<name> is not an id";
  Java passes the `BigInteger` on and security refuses it.
- **D29 `GetClientUsersPage`'s condition** is sent to security as the caller wrote it (checked
  the way `AbstractConditionDeserializer` reads it), not re-written by Jackson; a bad condition
  nested in a complex one is an unknown 500 "Invalid condition" (Java's text is Jackson's
  wrapping of the same refusal). The `Query` body has Jackson's fields without `pageable`.
- **D30 another service's refusal** (`D30_feign_debug_message`). When security, files or
  message refuses a core function's call (the caller-security functions, `FileToBase64`, the
  message family), core-exec answers that service's status and message (`fromFeign`); Java's
  `debugMessage` is Feign's exception text (method, URL, the downstream body), core-exec's is
  the message, or, for a coded refusal from a Rust security unit (passed on with its code), that
  unit's own detail, which starts with Java's text (`Access Denied: needs Authorities.User_READ`).
- **D31 `TemplateToPdf`'s renderer.** openhtmltopdf is replaced by the pdf-render sidecar
  (`deploy/pdf-render`, WeasyPrint: CSS with `<style>` and `@page`, tables, borders, colours,
  fonts, running headers, images) when `[pdf] upstream` is set (`crate::pdf_render`). The sidecar
  reads images only from the files service (any host's `/api/files/{static,secured}/file/...`)
  and `data:` URLs, Google Fonts (`fonts.googleapis.com`, `fonts.gstatic.com`: any family a
  template links, kept in memory after the first fetch) and `https` hosts listed in its
  `ALLOWED_HOSTS`; Java fetched any URL, so other external images are left out. WeasyPrint is not openhtmltopdf: a few CSS details lay out differently, and CSS 3 layout
  (flex) it supports where openhtmltopdf did not. Without `[pdf] upstream`, or when the sidecar
  fails and `[pdf] fallback_on_error` is on (off by default since 2026-10-22: a sidecar failure fails
  the call), `crate::pdf` makes the PDF: the HTML's text and
  structure (headings, emphasis, lists, tables side by side, `pre`, breaks, alignment, page
  breaks) in Helvetica / Courier on A4, characters outside WinAnsi as `?`, no images. Everything
  around it (template, language, parts, file name, the files upload, the output) is Java's.
- **D32 the definition marker's value.** Java's message, file, e-mail, AI, notification and event
  functions compare `DefinitionFunction.CONTEXT_KEY` with `"true"`; core-exec only knows whether
  a definition is running, so "present but not true" (which core never sets) is unreachable.
  Outside a definition they answer as Java does: 500 "Context does not contain key: KIRun
  Runtime" where Java uses `ContextView.get`, 403 "<function> can only be called from a server
  function" for the WhatsApp number and caller-security families, and `false` where Java uses
  `getOrDefault` (the schedule functions).
- **D33 approximate texts and orders.** Jackson decode errors, Gson's `getAsInt` /
  `getAsBoolean` edge cases and some null-pointer texts (`Tuples.of` without an app or client,
  `Path.getFileName()` of `/`) are worded close to Java's, not byte for byte. `SendWhatsapp`'s
  output keys are `result` then `sessionCode` (Java's `Map.of` order varies by JVM). Query
  strings encode a space as `+` (Feign writes `%20`).
- **D34 the scheduler's loop** is not in core-exec: core-exec writes and cancels one-offs and
  changes a client's schedule switch as Java does; claiming and raising is core-scheduler's,
  running is core-events' (step 4, below).
- **Not run by the live parity:** anything that would send (REST to a real target, e-mail,
  WhatsApp, calls, AI) or publish (events, notifications) on the Java side. Those are covered by
  the unit tests against in-process fakes.

### Data notifications and the retired message functions (2026-10-22, Rust only)

- **D42 `CoreServices.Notification.SendDataNotification`.** A push to the open browser tabs of
  one user (`User Id`) or of a client's users (`Client Id`, `Client Code`), optionally only
  those holding `filterAuthorization`, that is never stored (no `notification_inapp` row, no
  bell entry). Arguments: `appCode`, `clientCode`, `targetType`, `targetId`, `targetCode`,
  `filterAuthorization` (as `SendNotification`), `eventName`, `data` (any JSON) and
  `ttlSeconds` (1 to 3600, default 60); output `{sent}`. The caller and hierarchy checks are
  `SendNotification`'s (`connections::notification::prepare`), and only inside a server
  function. The event name is 1 to 64 letters, digits, `_ . -`, not `init` or `notification`;
  the data at most 64 KB as JSON (400s `CORE.DATA_NOTIFICATION_EVENT_INVALID`,
  `CORE.DATA_NOTIFICATION_EVENT_RESERVED`, `CORE.DATA_NOTIFICATION_TOO_LARGE`). The message goes
  on the notifications exchange with `kind: DATA`, `eventName`, `data` and `expiresAt`; the
  notification service delivers it (crates/notification/DIFFERENCES.md). Its signature is
  built in Rust (`data_notification_signature`), not captured from Java, and `repositoryFind` /
  `repositoryFilter` list it after the 72 functions Java has.
- **D43 `CoreServices.Message.*` fail at once.** The message service is retired. The seven
  functions (`SendWhatsapp`, `MakeCall`, `LinkWhatsappNumber`, `ListWhatsappNumbers`,
  `GetWhatsappPairingCode`, `RemoveWhatsappNumber`, `SetDefaultWhatsappNumber`) stay registered
  under Java's signatures, because stored definitions still name them (on the local stack,
  2026-10-22: eight leadzumptwo server functions), but each answers 410
  `CORE.MESSAGE_SERVICE_RETIRED` before its arguments are even validated, and calls nothing.
  The message client (`message_calls.rs`) and `[message] upstream` are removed;
  `CORE.WHATSAPP_*` and `CORE.MESSAGE_*_FORBIDDEN` are no longer raised.
- **D44 `CoreServices.REST.*` downloads in webhook and event runs.** With `downloadAsAFile`,
  a run holding `Authorities._Webhook` (the internal webhook route) or
  `Authorities._Event_Runner` (an event without its own authentication) stores the response
  through files' internal create route as a **secured** file of the run's client (or of a
  `fileClientCode` the run's client manages), where Java stored nothing for an anonymous
  caller. The file's `url` is files' answer: `api/files/secured/file/<CLIENT>/<fileLocation>/<name>`.
  Rules in crates/connections/DIFFERENCES.md (30).

### Step 4: core-scheduler and core-events (the Java `worker` retired)

- **D35 publish mode only.** core-scheduler is `EventScheduler` without a `ScheduledEventRunner`
  (Java's "no runner" mode): every claimed tick and one-off is published to the events queue and
  run by core-events. The in-process mode (run slots, `runConcurrency`, `busy`) does not exist;
  `EventSchedulerInProcessTest` is not ported and `PassReport.busy` is always 0. Claims, the
  catch-up rule, leases, SKIPPED rows, the shuffled order, the client status checks and the
  `schedule_run` / `scheduled_event` rows are Java's (same store, same unique indexes, so a
  Java and a Rust scheduler on one database never run a tick twice).
- **D36 the consumer.** core-events is `EventsQueListener` over lapin: one consumer per queue,
  acked when the run ends, rejected without requeue when the message cannot be read, nacked
  with requeue when the run fails before its action could run (Spring's defaults). Java's
  prefetch is unbounded; `[events] prefetch` (16) bounds the runs in flight per channel.
- **D37 task errors.** A task's error and detail are the Rust error's text plus the KIRun step
  traces (see "Event runs"); Java's detail is the JVM stack. A task type the listener has no
  executor for is "Invalid task type : <type>" as in Java; an EventAction whose task type is
  not one of Java's enum values fails Java's read instead.
- **D38 the anonymous event-runner context** carries Java's fields; its `createdAt` /
  `updatedAt` are the consumer's clock, written as Jackson writes `LocalDateTime`, and
  `accessTokenExpiryAt` is `LocalDateTime.MAX`'s text.
- **D39 cron** (`crate::cron`): Spring 6.2.1's `CronExpression` and `CronGrid`, checked against
  Spring itself (`tools/cron_fixtures.jsh` regenerates `src/cron_fixtures.json`: 351 crons, 676
  zone ids, 3,456 `next` chains, 480 tick cases). Where Spring throws inside `next` (a date past
  year 999,999,999) the functions answer no tick, and a tick beyond chrono's range (year
  ~262,000) is none, where Spring answers it. Error texts of a refused cron are close to
  Spring's, not identical. Spring's DST behaviour is kept: in New York `0 30 2 * * *` skips the
  spring-forward day and `0 30 1 * * *` fires twice on the fall-back day.
- **D40 time-zone data:** chrono-tz 0.10.4 carries tzdata 2025b (the JDK 25 the fixture came
  from); the local JDK 21.0.7 has 2025a and the production image may be older, so a zone whose
  rules changed since can tick at another instant than the Java scheduler. chrono-tz stops at
  2099; later years reuse the rules of a year just before 2100 (checked against the JDK to 2250).
- **J1 Java's run slots** (`J1_java_run_slots_full`, `tools/parity_core_scheduler.py
  --real-load`). Java's scheduler runs what it claims in-process with `runConcurrency` slots
  (4) and claims a tick only with a slot free; on a busy stack it reaches a tick late (caught up
  only as the latest missed one) or not at all. core-scheduler only publishes, so it claims every
  due tick. A tick only Rust claimed is expected; a tick only Java claimed is a difference.
- **J2 a never-run schedule can starve in Java (a Java bug, the same rule in Rust).** In
  `EventScheduler.runClient` a tick older than the fresh window (three passes, at least 60 s)
  is due only when a run was recorded before it: `lastRun(...).map(last -> last.getTickAt()
  .isBefore(tick)).defaultIfEmpty(FALSE)`, so a schedule with no recorded run starts only if a
  pass reaches its tick while it is fresh. Java claims a tick only with a run slot free; with its
  slots saturated it can miss the fresh window of a never-run schedule every time, and then never
  runs it. Seen on the local stack on 2026-10-15 (`--real-load`): 12 leadzumptwo client
  overrides `{enabled: true}` of the per-client spread schedules had never run on Java (clients
  active per security): FHSO, KAILA231, MODLI6, NAGES, PARAS, SHIVA133, TEMPA, TEST27, TEST34,
  TESTM (LZ_CAMPAIGN_METRICS) and KAILA241, NAGEN15 (LZ_CAMPAIGN_DISCOVERY). core-scheduler keeps
  Java's rule exactly (a new schedule never fires for a tick it never had); it has no run slots,
  so it reaches each fresh tick unless a whole pass takes longer than the fresh window, and these
  schedules ran on Rust in the same window. No change to which ticks run.
- **D41 a one-off's data numbers.** `ScheduleEvent` stores `data` through kirun-java's
  `JsonUtil.toMap`, which keeps a number's own Java type unless Gson parsed it lazily: a whole
  number from a stored definition's literal can arrive as a `Long` and is stored as Int64, where
  the Rust port stores an Int32 whenever the value fits (what a parsed number gives in Java).
  The raised event carries the same JSON number either way.
- **Local configuration:** `config/core-scheduler.toml` keeps the scheduler OFF and both units
  on a scratch exchange (`rs_scratch_events`) and scratch queues, because the local Java core
  runs its own scheduler and consumer on the same Mongo and broker.

### Platform functions (`CoreServices.Platform.*`, Rust only; step 4)

Java has no such family: the Java `worker` ran these jobs on Quartz and called the services
through Feign. Here they are core functions that the `platform` app's EventActions (client
SYSTEM) call on the schedules of its EventDefinitions (`tools/platform_seed/definitions.json`).
`functions/platform.rs`, the calls in `platform_calls.rs`; Java has nothing to compare, so the
parity tools do not cover them and the unit tests run every job against fake services.

- **P1 what each calls.** Every call is a `POST` with the worker's `@RequestParam`s and no
  authentication, read as Feign read it (empty is `null`, a refusal is the service's status and
  message), the answer passed on as the `output` event's `result`:

  | Function (defaults) | Calls |
  |---|---|
  | `RenewCertificates(daysBeforeExpiry=30)` | security `/api/security/ssl/internal/renew-certificates?daysBeforeExpiry` |
  | `CleanupTokens(unusedDays=90)` | security `/api/security/internal/tokens/cleanup?unusedDays` |
  | `Meter(service)`: security, core, entity-processor, files | `/api/security/internal/billing/meter/security`, `/api/core/internal/billing/meter`, `/api/entity/processor/internal/billing/meter`, `/api/files/internal/billing/meter` |
  | `ReconcileBilling(services=[security, core, files])` | `.../internal/billing/reconcile` of each named service (security, core, entity-processor, files), in the order given, each once, no `date`. The worker reconciled all four; entity-processor retired with the switch (2026-10-18), so the default and the seeded BILLING_RECONCILE leave it out |
  | `CleanupExpiredFiles(limit=500)` | files `/api/files/internal/{secured,static}/cleanupExpired?limit`, then `/{secured,static}/applyRetention?limit`, raising core `/api/core/events/internal/raise` (`FILES_EXPIRED`, `{resourceType, paths}`, 500 paths an event) per returned group, then entity-processor `/api/entity/processor/whatsapp/internal/media/stampExpired?retentionDays=30&limit=1000` |
  | `CleanupTransports(service, retentionDays=90, limit=200)`: ui or core | `/api/ui/transports/internal/cleanupOlderThan`, `/api/core/transports/internal/cleanupOlderThan` |
  | `CleanupEventRuns(retentionDays=90, successRetentionDays=7, staleAfterHours=6, limit=50000)` | core `/api/core/eventRuns/internal/cleanupOlderThan` |

  The defaults are the worker's code defaults; the seeded job data (SSL `daysBeforeExpiry=3`, the
  rest equal to the defaults) is passed by the platform app's job functions (P5). `service` has
  no default (the worker refused to guess) and is trimmed and lower-cased.
- **P2 the guard.** Each runs only when `context::event_action()` is set (only core-events sets
  it, around one EventAction's tasks), that action is app `platform` and client `SYSTEM`
  (compared exactly), the caller is the event runner (`Authorities._Event_Runner`: the event was
  raised without a caller, by the scheduler; `CoreServices.Event.CreateEvent` lets any server
  function raise any app's event for any client, carrying the raiser's authentication), and no
  definition owned by another app is running (`context::owner_app_code()` is none or
  `platform`). Otherwise 403 "CoreServices.Platform.<name> runs only as a task of the platform
  app's events", before the arguments are read and with no call made: the execute route (signed
  in or anonymous), a page's or request's server function (the platform app's own included),
  another app's or client's EventAction, the platform action of an event a caller raised, another
  app's function run inside a platform action. A task spawned off the action does not carry it.
- **P3 not listed.** `functions/repositoryFind` and `repositoryFilter` leave the family out for
  every app but `platform` (Java lists none). Execution still resolves them, so a call from
  another app is the guard's 403, not a 404.
- **P4 failures.** A one-call function fails with the service's status and message, so the event
  run reads FAILED with the reason; the worker caught SSL, token and metering errors and wrote
  "Error: ..." into `LAST_FIRE_RESULT` as a completed fire. `ReconcileBilling` and
  `CleanupExpiredFiles` make every call whatever the others did (the worker's independence) and
  then fail with 502 naming each failed call and what every call answered. A refused or failed
  `FILES_EXPIRED` raise and a failed WhatsApp stamping stay best effort as in the worker:
  counted (`eventsFailed`) and listed in `errors`, never a failure.
- **P5 where the job parameters live.** A CALL_CORE_FUNCTION task passes only the event's data
  (under `functionParameterName`), and a scheduled tick's data is just its `_schedule` marker, so
  the job data cannot ride on the task. Each job's EventAction calls a stored function of the
  platform app, `Platform.Jobs.<JOB>` (`executeAuth: Authorities._Event_Runner`, so only the
  event runner may run it), whose one step calls the platform function with the worker's job data
  as literal arguments. Changing a job's parameters is editing that function, as it was editing
  the task row's `JOB_DATA`; its schedule is the EventDefinition's.
- **P6 schedules.** The Quartz crons are written as the five fields `CronGrid` takes (it
  prepends second 0; every worker cron fired at second 0): `0 0/15 * * * ?` is `*/15 * * * *`,
  `0 0 2 * * ?` is `0 2 * * *`, and so on, UTC, `perClient: false` (one run, for SYSTEM). The
  scheduler's catch-up rule replaces Quartz's misfire handling.
- **P7 not carried over from the worker.** `worker_tasks`' `LAST_FIRE_TIME` / `LAST_FIRE_RESULT`
  (the event run log has the outcome), the 2000-character result truncation, the per-call
  five-minute `runWithTimeout` (here the HTTP client's 300 s per call, the same bound), and the
  per-client schedule control (`worker_client_schedule_controls`): the EventDefinition's
  `schedule.enabled` switches a job off.

### Event runs (step 4: `EventRunService`, the run log routes, `CoreInternalEventController`)

Tagged `ER` so they do not collide with the step's other `D` entries.

- **ER1 step traces are collected beside the run.** kirun-java 4.9.2 adds a `KIRuntimeStepTrace`
  to the step's exception; kirun-rust's errors are text, so `step_trace::traced` collects them
  instead: inside it `DefinitionFunction` runs its runtime on a function repository whose
  functions record a trace when they fail (`step_trace::instrument`, `in_definition`). Same
  content (function, step, step function, bounded and masked arguments in Gson's text, or
  "before its arguments were evaluated"), innermost first, at most 20. The `DebugCollector`
  is not used: it keeps only 10 executions, needs `debug_mode` (every step's arguments and
  results copied) and is process-wide.
- **ER2 the arguments are read when the step fails**, from what its function holds: for a
  function validated against its signature, the validated arguments, kept to the statement's
  parameters that have references and a non-null value, in Java's `HashMap` order. A value the
  validation filled in or converted shows that way; Java shows the evaluated arguments.
- **ER3 a failure before the arguments are worked out.** kirun-rust's error names the
  expression, not the step: the trace goes on the first step of the definition with an
  `EXPRESSION` argument the error quotes (white space and brackets ignored). Two steps with the
  same expression: the first is named. A nested `{{ }}` part or an `executeIftrue` that cannot be
  evaluated names no step (Java traces only the arguments case too).
- **ER4 what is kept.** A step or definition that succeeds drops the traces of failures inside
  it (they were handled), as an exception that is caught takes its traces with it. Steps the
  runtime runs together that both fail are both listed (Java keeps the error that won). Work a
  function spawns onto another tokio task is not traced.
- **ER5 the detail has no stack.** `detail_of` is the steps (three with arguments, then where
  each is), a blank line, then the error and up to four causes, one per line, each its own text
  (`Caused by: ` before a cause; a `CoreError` with its status, `500 Internal Server Error:
  ...`). Java prints each exception's class and frames, folding Reactor's. An error with no
  message is written as its debug form (Java: the class and the first frame of our code).
  `error_of` uses a `CoreError`'s message without the status, as `GenericException.getMessage`.
- **ER6 lengths** are UTF-16 units as in Java (4000 for errors, 12000 for details, 2000 / 200 for
  arguments); a cut never splits a surrogate pair (Java can leave half of one). Numbers in the
  arguments are written as kirun-rust holds them (D1).
- **ER7 a refused read.** `@PreAuthorize("hasAuthority('Authorities.EventAction_READ')")`: a
  signed-in caller without it gets 403 `text/plain` `Access Denied`
  (`HttpStatusServerAccessDeniedHandler`), an anonymous one a bare 401 (Spring Security 6.4.2's
  `ExceptionTranslationWebFilter`, read from its source, not compared live). The service checks
  again and answers a `CoreError` 403 `Access Denied` when called directly.
- **ER8 parameter errors.** A parameter that does not convert is 400 with `debugMessage`
  `400 BAD_REQUEST "Type mismatch."` (Spring 6.2.1's `ResponseStatusException.getMessage`; D16
  applies). `from` / `to` beyond chrono's range (about 262,000 years) are a 500 with Java's
  `Invalid value for EpochDay` text, where Java accepts up to a billion years and then fails in
  MySQL. A `cleanupOlderThan` retention that reaches past that range deletes nothing (Java
  computes the date and asks MySQL).
- **ER9 the sweep's answer** is written `runsRemoved`, `successesRemoved`, `staleClosed`; Java's
  `Map.of` order differs from one JVM run to the next.
- **ER10 a raised event's `data`** goes on the wire in Java `HashMap` order
  (`EventMessage::to_json`), where Java keeps the order Jackson read the body in. The request's
  content type is not checked (Java answers 415 to a body that is not JSON by its header). A
  number in a text field reads as its shortest form (Jackson keeps the body's text, `1.50`).
- **ER11 display text.** Zones are chrono-tz's database (the JVM has its own copy); `ZoneId.of`
  is followed for region ids, offsets and `UTC` / `GMT` / `UT` with an offset. A schedule
  marker's `tickAt` / `runAt` is read as RFC 3339 with an upper-case `T` (`Instant.parse`; a
  lower-case `z` is accepted here).
- **ER12 small things.** The table is named without its schema (`core_event_runs` in the pool's
  database; jOOQ writes `core.core_event_runs`). An event without a name is not a hand-off (Java's
  `Set.of(...).contains(null)` throws). A null in security's `filterManagedClientCodes` answer is
  dropped (Java would fail on it). The switch is `[core.event_runs] enabled` (Java
  `core.eventRuns.enabled`).
- **ER13 a page window MySQL refuses** (`ER13_mysql_error_text`). `from` / `to` are epoch
  seconds; one past year 9999 (milliseconds sent by mistake) is refused by MySQL ("Incorrect
  DATETIME value"), an unknown error on both. Java's `debugMessage` is jOOQ's (the SQL, then the
  driver's message), core-exec's is the driver's message alone.

### Step 5: core-editor (the editing surface, port 8111)

core-editor serves every core controller that is not core-exec's, core-scheduler's or
core-events': the CRUD, drafts, fork and publish of functions, schemas, storages, connections,
templates, notifications, event definitions, event actions, workflows, workflow actions and
fillers; versions, publish-all, transport, `DELETE /api/core`; the event definitions' schedule
routes, the template previews, `notifications/internal/{name}`, the index, the caches and
billing. It also serves the run log and the event raise (step 4's routes, still on core-exec too),
so every internal route the platform jobs call is on one unit. The write path is the
`overridable` crate's (its `DIFFERENCES.md` holds too); `tools/parity_core_editor.py` checks it,
the evictions each write publishes included. Tags are the parity script's case names.

- **E1 the library's security fixes stay.** `create` never takes an id from the body (Java's
  `repo.save` upserted by it, so a caller allowed to create in its own client could overwrite
  any document); the cached list checks access before it is served; version reads are checked
  (`POST /versions/{id}/query` was unchecked); `clientOnly` on a list works (any value answered an
  empty page); `DELETE /api/core` evicts every name's caches, live and draft.
- **E2 filler, notification and workflow history** (`... version by id`). Java's
  `VersionService.mapAuthName` has no name for `FILLER`, `NOTIFICATION` and `WORKFLOW`, so its
  `GET /versions/{id}` refuses their rows to everyone (an empty 200) while the query showed them
  to anyone. With every version read checked, the editor maps them to `Application` (the
  filler's access-check name), `Notification` and `Workflow` (`EDITOR_AUTH_NAMES`).
- **E3 nested classes on a draft save.** A create or an update reads `StorageRelation`,
  `StorageIndex`, the column definitions, `EventActionTask`, `EventSchedule`,
  `NotificationTemplate`, `TriggerWorkflowStep` and the enums as Jackson does (unknown keys
  dropped, field defaults filled, an unknown constant a 400). A draft save stores its body as
  sent (the library's draft path has no hook); the classes are read when the draft is published.
- **E4 explicit nulls in a body.** `isAppLevel` / `onlyThruKIRun` of a connection and a
  notification's `notificationType` sent as `null` are stored as `false` / `INFO`, the values
  Java reads such a document back as (Java stores nothing and answers the create without them).
- **E5 a workflow trigger's `stepType`** is stored with the trigger. Java writes it only in
  JSON (a getter), into the version snapshots too; the answers are the same.
- **E6 a storage delta whose `textIndexFields` the base has and the body drops** is stored as
  null; Java fails with a `ClassCastException` (500).
- **E7 a derived storage with no copy anywhere up its base chain** is created with a new table
  name; Java's create comes back empty (a 200 with no body).
- **E8 definition trigger arguments** (`BEFORE_UPDATE_STORAGE` ... `AFTER_DELETE_STORAGE`) are
  the storage document as JSON with its nulls left out; Java hands the functions Gson's tree of
  the bean, so a field the bean holds in another shape (the dates) can read differently.
- **E9 order** (`write transport export`, `write transport import`). An export's objects are in
  service order; Java reads the services concurrently and writes them as they finish.
- **E10 template previews** render with the FreeMarker subset `crates/connections` implements
  (`process_lenient`: an element that fails is skipped, as `IGNORE_HANDLER` does), and the PDF
  with the same renderer as `CoreServices.File.TemplateToPdf` (D31).
- **E11 the schedule zones** are chrono-tz's IANA regions; Java lists its JDK's tz database. The
  two lists match locally; a tz release can add or rename a region on one side first.
- **E12 a refused anonymous caller.** Anything outside core's permitted paths answers an
  anonymous caller with a bare 401, without `WWW-Authenticate` (D15). As in Java, where Spring
  Security runs before routing, that includes paths nothing maps and methods a path does not
  take, in core-editor and core-exec alike (`crate::unmapped`); a signed-in caller there gets the
  dispatcher's 404 / 405 as `ControllerAdvice` writes it, without the `Allow` header axum adds.
- **E13 key orders Java picks per JVM run.** A page's `pageable` (`paged`/`unpaged`) and its
  sort orders (`ascending`/`descending`), whose getters Jackson lists in `getDeclaredMethods`
  order, which HotSpot sorts by symbol address, and a schedule zone's `zone`/`label` (`Map.of`,
  iterated in a per-run salted order) come out in either order from one Java restart to the
  next (measured: the core restarted at 21:01 on 2026-10-15 flipped all three). Rust writes one
  fixed order, the one Java core showed when this was ported; the parity script reports these
  as expected.

Java's own behaviour kept (not differences, listed so nobody "fixes" them by accident):
`TransportService` exports and imports schemas, storages, functions, templates, event
definitions, event actions and fillers only (no connections, notifications, actions or
workflows); `DeletionService` leaves notifications out of an app's wipe; a workflow without a
trigger is a 500 (`workflow_trigger_missing`), and one with any step is a 500 (Jackson cannot
make the abstract `WorkflowStep`); `Notification.extractDifference` fills its unset scalars from
the base rather than clearing what equals it; a delete evicts only the deleting client's cache
key; `uniqueName` and a relation's `uniqueRelationId` are cut near 18 letters before their
random suffix, as `UniqueUtil.uniqueName` cuts them. core's `unknown_error_with_id` text has no
trailing space, unlike ui's, which the library writes; core-editor writes core's, and the
`Page` / `Sort.Order` property order core's JVM showed (E13).

## K: kirun-rust (kirun-js) vs kirun-java (all resolved 2026-10-17)

Each was fixed in the `kirun` crate (not here) so that it answers as kirun-java 4.9.2; the parity
scripts no longer have `K` rules, and every case they had is `SAME` (the `kirunlive` date
functions' clock-dependent fields are compared within 5 seconds). kirun-java tests were ported
into the crate (`tests/**/java_parity_test.rs`, with 500 operator and 944 date cases measured on
kirun-java).

- **K1 variable arguments keep nulls** (`K1_variable_argument_nulls`). Resolved 2026-10-17:
  a variable argument drops `null` values, as kirun-java's
  `ReactiveKIRuntime.getArgumentsFromParametersMap` (cxapp `fetchingRecordsFromStoragesSorted`
  answers its output).
- **K2 `System.Object.ObjectConvert` with a `$ref` schema** (`K2_object_convert_ref`).
  Resolved 2026-10-17: the conversion no longer requires a `type`; a `ref` is resolved and
  converted to, a typeless schema leaves the value as it is, and refusals read as kirun-java's
  (cxapp `abc`, rim `objectCreation`).
- **K3 date functions** (`K3_date_functions`). Resolved 2026-10-17: `System.Date.*` follow
  kirun-java's `java.time` code instead of luxon: names and outputs (`FromDateString` outputs
  `isoTimeStamp`), `ZoneId.of` zones (`local` is refused), Java formatter patterns and texts
  (`am`), weeks by locale (Sunday for en_US / en_IN), epoch units, `Difference`, the default
  zone and locale of the process (as the JVM's: `TZ` or `/etc/localtime`; `KIRUN_LOCALE`, else
  `LC_ALL` / `LC_TIME` / `LANG`, `C` read as en_US). The local Java core's JVM runs en_IN, so
  core-exec and core-editor are started locally with `KIRUN_LOCALE=en_IN`; a deployment sets it
  to the Java core's JVM locale. All `kirunlive` functions match.
- **K4 INTEGER range** (`K4_integer_range`). Resolved 2026-10-17: an `INTEGER` schema refuses a
  whole number outside the `int` range (`9007199254740993 is not a number of type Integer`), a
  `LONG` one outside `long`, as kirun-java; the storage create answers 500 as Java does.
- **K5 a bare word as an expression** (`K5_bare_word_expression`). Resolved 2026-10-17: a word
  that is not a path or a number evaluates to its text, as kirun-java (cxapp
  `getTransactionById`, `gettingTotalAmountPaidOfBooking`).
- **K6 a value that comes to nothing** (`K6_null_value_java_npe`). Resolved 2026-10-17:
  kirun-rust tells a missing value (Java `null`) from a JSON `null` where kirun-java does and
  fails with kirun-java's NullPointerException text and status (crmai `getUserRoles`: `t2`;
  kyc `getFilteredKycsByUserId` over GET: `value`).
