# What crates/core needs from elsewhere

Worked around inside crates/core where possible; each entry says how.

## kirun (`nocode-kirun/kirun-rust`)

1. **kirun-java behaviour for stored server functions** (DIFFERENCES K1 to K6). Resolved
   2026-10-17 in kirun-rust (owner decision: stored server functions return what they return
   today, so kirun-rust answers as kirun-java 4.9.2 for variable arguments, schema conversion
   and validation, dates, integer range, expression evaluation and null handling; also
   `System.Math` result types). The change sits in the nocode-kirun working tree, unreleased;
   what is left for the crate owner:
   - release it (crate version unchanged so far) and decide whether kirun-js follows (the
     browser runtime still answers as kirun-js);
   - the deployment of core-exec sets `KIRUN_LOCALE` (and `TZ`) to the Java core's JVM locale
     and zone, since `System.Date.*` print by the process default as the JVM does;
   - known kirun-java answers not reproduced (listed in kirun-rust `DESIGN.md`): `float`
     arithmetic on decimals read from JSON text, `NaN` / `Infinity` results, hash-ordered type
     lists in `[Expected: ...]` messages, last-digit results of trigonometric and hyperbolic
     functions.
2. **Nested definition functions.** kirun-rust gives fresh parameters (own context, steps,
   events, values map without `Arguments.` / `Steps.` / `Context.`) only to its own
   `KIRuntime` (`as_any().is::<KIRuntime>()`); kirun-java does it for every
   `IDefinitionBasedFunction`. Worked around: core's `DefinitionFunction` builds those
   parameters itself when it runs as a step. A marker trait (or a `Function` method) in kirun
   would remove the workaround.
3. **`Repository::find` has no error channel** (DIFFERENCES D10). A failing lookup during a run
   reads as "not found". Worked around for the top-level lookups only (core uses its own
   `FunctionSource` / `SchemaSource` traits there).
4. **Carrying a status through a run.** `KIRunError` holds text only, so a core function's
   `GenericException` status (400, 403, ...) cannot travel up the runtime. Worked around: the
   request context keeps the last raised error and the edge matches it by text.

## platform

1. **The whole `securityContextAuthentication` answer.** `SecurityClient::context_authentication`
   parses only some fields; `GetAuthentication` / `GetUser` need the whole user and
   entity-processor calls need `accessToken`. Worked around: `crates/core/src/auth.rs` makes the
   same call itself and keeps the raw JSON. An additive `context_authentication_raw` in
   platform would let it go.
2. **`IFeignSecurityService.getAppUrl`** (plain text) is not in `SecurityClient`. Worked around
   in `crates/core/src/clients.rs`.

## overridable

Nothing missing: `Store::read`, `inheritance_order` and `find_docs` cover the function, schema,
storage, connection and event-definition reads. The editor (step 5) needs the write path
(`extract_difference` for `Storage`, which `StorageFlagsOverrideTest.equalFlagsAreNotStored`
and `StorageRelationDiffTest` pin).

## appdata

1. **An ObjectId value.** A row the Mongo engine has just inserted carries its relation
   ObjectIds as Jackson's bean (`{timestamp, date}`), which has lost the hex id. Java's eager
   fill reads the id with `toString()`. Worked around (DIFFERENCES D22) with the ids the row was
   written with; a `Value` variant that keeps the hex (and writes the bean) would remove it.
2. **`DraftCopyFilter::from_value` and `TenantProgress::to_value`** are not in the crate.
   Worked around: `functions::storage::draft_copy_filters` reads the filters as Jackson does,
   `data_routes::tenant_progress` writes the record.
3. The engines' `Hooks.authority` is plugged with core's KIRun evaluator
   (`authorities::KirunAuthorityCheck`), as the crate's DIFFERENCES asks.

## connections

Wired in step 3 (`crate::integrations`): the crate's traits (`ConnectionStore` / `TemplateStore`
over the overridable store, `TokenStore` as `TokenDao` over core's MySQL pool,
`AuthTokenFunction` over core's executor, `HierarchyChecks` over security, `DownloadSink` over
`files_calls::FilesCalls`, `Publish` over RabbitMQ or dropped), the KIRun wrappers
(`functions::integration_fns`), the routes (`connection_routes`), the configuration
(`[connections]`, `[mq]`) and the publishers (`integrations::Mq`). The cache eviction listener
is started once by `run_exec`.

1. **The owner's decisions** listed in `crates/connections/NEEDS.md` (its DIFFERENCES 19 to 24,
   and the two Java bugs it fixes) still stand; core-exec inherits them.

## deployment configuration (`config/core-exec.toml`, outside this crate)

1. **RabbitMQ.** Publishing is off until a broker is configured: `[mq] host`, `port`,
   `username` (and `MODLIX__MQ__PASSWORD`), or one `MODLIX__MQ__URI`. The URI and password are
   never logged (`MqSection`'s `Debug` hides them). `events_exchange` / `events_routing_keys` and
   the notification pair default to Java's.
2. **The files service**: `[files] upstream` defaults to `lighthouse:FILES`. The message
   service is retired and core no longer calls it (`[message]` is gone; a leftover section is
   ignored).
3. **The scheduler's one-off settings**: `[core.scheduler]` defaults to Java's
   `EventSchedulerSettings`.
4. **The platform functions' services** (`CoreServices.Platform.*`, for core-events):
   `[core] upstream` (default `lighthouse:CORE`) and `[ui] upstream` (default `lighthouse:UI`) are new;
   security, `[entity_processor]` and `[files]` are the existing upstreams. `[core] upstream`
   must reach instances that serve the Java core's internal routes (`internal/billing/meter` and
   `reconcile`, `transports/internal/cleanupOlderThan`, `eventRuns/internal/cleanupOlderThan`,
   `events/internal/raise`); a unit that registers as `CORE` without them would answer the jobs
   404. An upstream the configuration cannot make (a `lighthouse:` one without `[registry] zones`)
   is logged at startup and fails only the jobs that need it.

## core-scheduler and core-events (step 4): deployment

1. **Configuration.** Both read `CoreConfig` (`config/core-scheduler.toml`,
   `config/core-events.toml`): core-scheduler needs `[mongo]` (the same database Java core uses,
   for `eventDefinition`, `schedule_run`, `scheduled_event`), `[database]` (the run log), `[redis]`,
   `[security]`, `[core.scheduler]` (Java's `core.scheduler.*` in snake case, `enabled` true by
   default) and `[mq]` for the `events` exchange; core-events needs what core-exec needs plus
   `[mq]` and `[events] queues` (`events1,events2,events3`), `prefetch`, `declare` (false: the
   queues exist). The broker URI or password comes from `MODLIX__MQ__URI` /
   `MODLIX__MQ__PASSWORD`.
2. **Cutover, in order:** stop the Java worker; set `core.scheduler.enabled=false` on every Java
   core still running; take Java core off the events queues (its `EventsQueListener` would compete
   with core-events, and it has no `CoreServices.Platform.*`); start core-scheduler (two
   instances: the unique claims make any number safe) and core-events (scale on queue depth);
   then apply the platform transport. A Java and a Rust scheduler sharing the claim store never
   run a tick twice, so the overlap is safe for the schedules themselves.
3. **Health:** each serves `/readyz` (mongo, mysql) on its port (8108, 8109) and nothing else.

## core-events (step 4), for the platform functions

1. **The action scope.** Wrap exactly one EventAction's tasks in
   `context::with_event_action(EventActionRun { app_code, client_code, event_name }, ...)`, with
   the event's app and client, and run the tasks inside that future (a spawned task loses it,
   and the guard then refuses).
2. **The event runner's context.** Run a scheduled tick under Java's anonymous event-runner
   context (`EventsQueListener.makeAnonymousContextAuth`: authorities `Authorities._Anonymous`
   and `Authorities._Event_Runner`): the platform app's job functions carry
   `executeAuth: Authorities._Event_Runner`, and the guard of `CoreServices.Platform.*` requires
   it too; without it both refuse (403).
3. **No Java consumer of the events queues once the platform schedules are on.** A platform
   tick taken by a Java core's `EventsQueListener` fails (Java has no `CoreServices.Platform.*`),
   and with the worker still running every job would run twice. Apply the platform transport at
   cutover (worker stopped, Java `core.scheduler.enabled=false`, Java core off the events queues).

## The platform app (`tools/`)

1. **Seed on local**: `tools/seed_platform_app.py [--dry-run] [--enable-schedules] [--prune]`
   creates the security app `platform` (SYSTEM) and its 10 job functions, EventDefinitions and
   EventActions from `tools/platform_seed/definitions.json` through the APIs, idempotently, LOCAL
   only; `--prune` deletes, through the APIs, what the app holds that the seed no longer lists
   (ENTITY_PROCESSOR_METERING went that way on 2026-10-18, when entity-processor retired).
   Schedules are written off on local unless `--enable-schedules` (TOKEN_CLEANUP must not run
   against the local security).
2. **Transport**: `tools/make_platform_transport.py [--out FILE]` exports the 30 objects from
   local into a core transport file (schedules set on, from the seed), checks it against the seed
   and writes a manifest with the steps to apply it. Security is not transported: the manifest
   carries the app's fields for `POST /api/security/applications` on the target.
