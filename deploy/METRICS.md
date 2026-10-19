# Metrics of the Rust units

Every unit serves Prometheus text on `/metrics` (its own port, no authentication), through the
`metrics` facade and the recorder `platform::telemetry::init` installs. This page lists every
family a unit exports, for building the dashboards and alerts.

## How they are collected

- Each unit registers in Lighthouse (and, during the migration, Eureka) with `metrics.path=/metrics`
  and `management.port=<port>` in its instance metadata.
- On each app host, Alloy discovers the units from the host's Lighthouse pair (Eureka API on
  8761 and 8762), scrapes them every 15 seconds and pushes the samples to the central Prometheus.
  Lighthouse itself is scraped directly on both ports (`job="lighthouse"`).
- Gauges that read a current value (process, runtime, database pools) are read when `/metrics` is
  scraped, so they are as fresh as the scrape.

## Labels on every series

| Label | Set by | Value |
|---|---|---|
| `service` | the unit | its binary name (`core-exec`, `gateway-rust`, ...) |
| `environment` | the unit | `[telemetry] environment` |
| `exported_instance` | the unit | `[telemetry] instance`, else `HOSTNAME` (the unit exposes it as `instance`; the scrape's own `instance` wins and renames it) |
| `job` | Alloy | the registered app name in lower case (`core-exec`, `gateway`) |
| `instance` | Alloy | the registry instance id, `<hostname>:<app>:<port>` |
| `colour` | Alloy | `blue` or `green` when the hostname ends in it (or in `-blue-2`, a second instance); absent otherwise |
| `env`, `host`, `role` | Alloy | the host's environment, name and role |

Labels are kept bounded on purpose: routes are route templates, outbound targets are service
names from a fixed list, cache names keep only their fixed part, and no label ever carries a raw
path, an id, a client code or an address taken from a request.

## Every unit (crates/platform)

### HTTP

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `http_server_request_duration_seconds` | histogram | `method`, `route`, `status` | Requests the unit answered, from the first byte in to the response head out. `route` is the Spring route template the handler reported (`/api/core/data/{storage}`), `unmatched` when none did, and for the gateway the id of the route config that matched. |
| `http_client_request_duration_seconds` | histogram | `target`, `method`, `status` | Calls to other services, until their response headers. `status` is the response's code, or `connect_error`, `timeout` or `error` when there was none. A call retried on another member (refused connection) counts once per attempt. |

`target` is the called service, named from the path: `security`, `core`, `ui`, `files`,
`message`, `notification`, `multi`, `ai`, `entity-processor`, `entity-collector`, `other`.
Calls outside Modlix use a fixed name: `sendgrid` (notification's mail), `definition-url` (multi
reading a transport definition from the caller's address).

Covered callers: the platform `Upstream::send` (and so every `SecurityClient` call, in every
unit), core's service clients (security, entity-processor, files, message, the platform calls
and the caller-authenticating calls), notification's core and security clients and its SendGrid
call, and multi's calls to the other services. Not covered yet: the gateway's proxied traffic
(it has its own `gateway_*` families), the ui shell's and security admin's own reqwest calls,
and calls to third parties made by KIRun functions.

Buckets (seconds), for both histograms: 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10,
30.

### Process

From `metrics-process`, at each scrape (Linux `/proc` on the hosts).

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `process_cpu_seconds_total` | counter | | User and system CPU time. In whole seconds (the facade's counters are integers): use `rate()` over 5 minutes or more. |
| `process_resident_memory_bytes` | gauge | | Resident memory. |
| `process_virtual_memory_bytes` | gauge | | Virtual memory size. |
| `process_virtual_memory_max_bytes` | gauge | | The address space limit (huge when unlimited). |
| `process_open_fds` | gauge | | Open file descriptors. |
| `process_max_fds` | gauge | | The descriptor limit. |
| `process_threads` | gauge | | OS threads. |
| `process_start_time_seconds` | gauge | | Start time, Unix seconds (`time() - process_start_time_seconds` is the uptime). |

### Runtime and build

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `tokio_runtime_workers` | gauge | | Worker threads of the Tokio runtime. |
| `tokio_runtime_alive_tasks` | gauge | | Tasks alive in the runtime (in-flight requests, background loops). A steady climb is a task leak. |
| `tokio_runtime_global_queue_depth` | gauge | | Tasks waiting in the runtime's global queue. Above zero for long means the workers cannot keep up. |
| `build_info` | gauge | `service`, `version`, `commit` | Always 1. `commit` is the `GIT_SHA` the binary was built with (CI sets it), `unknown` for a local build. Join on it to see which commit each instance runs. |

### Databases, Redis, caches, errors

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `db_client_connection_count` | gauge | `system` (`mysql`, `mongodb`), `pool`, `state` (`idle`, `used`) | Open connections of the unit's database pool. `pool` is the database name. MySQL is read from the sqlx pool; MongoDB is counted from the driver's pool events. |
| `db_client_connection_max` | gauge | `system`, `pool` | The most connections the pool opens. `used / max` near 1 means requests wait for a connection. |
| `redis_errors_total` | counter | `operation` (`connect`, `command`, `subscribe`) | Redis calls that failed: eviction publishes and deletes, and the eviction channel subscription (`subscribe` also counts a subscription that dropped). Any rise means cache evictions may not have reached the other instances. |
| `cache_gets_total` | counter | `cache`, `result` (`hit`, `miss`) | Local cache lookups. The name and labels are Micrometer's for Caffeine, so Java and Rust can share a panel. |
| `cache_evictions_total` | counter | `cache` | Local cache entries dropped for size or age (not the evictions the services publish). |
| `coded_errors_total` | counter | `code`, `status` | Every coded error a unit answered with (`SEC.APP_ACCESS_FORBIDDEN`, `COMMON.INTERNAL_ERROR`, ...), with the HTTP status sent. Errors relayed from another unit count where they are answered too. |

`cache` is the fixed part of the Java cache name: the leading letters (`UIFunctionCache`,
`profileAuthsById`, `fsGetDetail`), or the fixed tail of storage caches (`table_creation`,
`index_creation`, `foreign_keys`).

Only pools a unit opens through `platform::db` are exported. The per-tenant pools appdata opens
for app data connections are not.

## core-scheduler

From each pass (every `core.scheduler.tick_ms`). `kind` is `cron` (a recurring schedule's tick)
or `once` (a scheduled one-off).

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `core_scheduler_passes_total` | counter | `result` (`ok`, `failed`) | Passes run. A failed pass still counts what it did before failing. |
| `core_scheduler_claimed_total` | counter | `kind` | Ticks and one-offs this instance claimed. |
| `core_scheduler_published_total` | counter | `kind` | Claims published to the events queue. |
| `core_scheduler_skipped_total` | counter | `kind` (`cron`) | Ticks claimed and closed as SKIPPED: the previous tick's run was still going. |
| `core_scheduler_failed_total` | counter | `kind` | Claims not published: the raise failed, a one-off was given up on, or its client is not active. |
| `core_scheduler_lost_total` | counter | `kind` (`cron`) | Ticks another instance claimed first. |

`claimed = published + skipped + failed` for each kind.

## core-events

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `core_events_consumed_total` | counter | | Deliveries taken off the events queues. |
| `core_events_acked_total` | counter | | Deliveries acked (the run ended). |
| `core_events_nacked_total` | counter | `requeue` (`true`, `false`) | Deliveries nacked: requeued because the run failed before its action ran, or dropped because they could not be read. |
| `core_events_failed_total` | counter | `reason` (`unreadable`, `run`, `settle`) | What went wrong: a body that cannot be read, a run that failed, an ack or nack the broker did not take. |

## notification

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `notification_consumed_total` | counter | | Deliveries taken off the notification queues. |
| `notification_sent_total` | counter | `channel` (`email`, `in_app`) | Notifications sent: each mail attempted, and each in-app send. |
| `notification_failed_total` | counter | `reason` | Deliveries that sent nothing: `unreadable`, `no_connection`, `no_notification`, `no_channel`, `no_users`, `error` (the send failed), `panic`. Every delivery is acked whatever happened, as Java's listener does, so this is the only place a failure shows. |

## gateway-rust

Owned by `crates/gateway`; every series of a pool exists from the start, at zero. `pool` is a
pool name from the gateway's configuration.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `gateway_retries_total` | counter | `pool`, `reason` (`connect`, `5xx`) | Requests retried on another instance. |
| `gateway_retry_budget_exhausted_total` | counter | `pool` | Retries refused because the pool's retry budget was spent. |
| `gateway_pool_ejections_total` | counter | `pool`, `reason` (`connect`, `5xx`) | Instances taken out of a pool. |
| `gateway_pool_ejected_instances` | gauge | `pool` | Instances out of the pool now. |
| `gateway_pool_healthy_instances` | gauge | `pool` | Instances passing their health check now. |
| `gateway_pool_breaker_state` | gauge | `pool` | The pool's circuit breaker: 0 closed, 1 half open, 2 open. |
| `gateway_pool_breaker_rejections_total` | counter | `pool` | Requests answered at once because the breaker was open. |

## Lighthouse

Owned by `crates/lighthouse` (the registry) and `crates/lighthouse-client` (in every unit that
registers or watches). `peer` is a configured peer URL.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `lighthouse_instances` | gauge | | Instances in this member's registry. |
| `lighthouse_registrations_total` | counter | `origin` (`client`, `peer`) | Registrations received. |
| `lighthouse_renewals_total` | counter | `result` (`renewed`, `not_found`, `newer_elsewhere`, `conflict`) | Lease renewals. |
| `lighthouse_cancels_total` | counter | `origin` | Instances removed on request. |
| `lighthouse_evictions_total` | counter | | Instances evicted for an expired lease. |
| `lighthouse_eviction_ticks_skipped_total` | counter | | Eviction ticks skipped because they ran late (a paused or starved process must not evict everyone). |
| `lighthouse_self_preservation` | gauge | | 1 while self-preservation holds evictions back. |
| `lighthouse_renewals_last_minute` | gauge | | Renewals in the last minute. |
| `lighthouse_renewal_threshold` | gauge | | The renewals per minute below which self-preservation starts. |
| `lighthouse_tombstone_refusals_total` | counter | | Late replicated registrations refused for an instance just cancelled. |
| `lighthouse_replication_batches_total` | counter | `peer`, `result` (`ok`, `failed`) | Replication batches sent to a peer. |
| `lighthouse_replication_dropped_total` | counter | `peer`, `action` | Replication messages dropped because the peer's queue was full (heartbeats first). |
| `lighthouse_replication_queue` | gauge | `peer` | Messages waiting for a peer. |
| `lighthouse_digest_repairs_total` | counter | | Instances taken from a peer's digest that this member was missing or held older. |
| `lighthouse_config_snapshots_total` | counter | `from` | Configuration snapshots served, by source. |
| `lighthouse_client_registrations_total` | counter | `result` (`ok`, `failed`) | A unit's registrations. |
| `lighthouse_client_heartbeats_total` | counter | `result` (`ok`, `not_found`, `failed`) | A unit's heartbeats. |
| `lighthouse_client_watch_polls_total` | counter | `result` (`fresh`, `unchanged`, `kept`, `empty_unconfirmed`) | A watcher's registry polls. |

## For the dashboards

- Request rate and errors: `sum by (job) (rate(http_server_request_duration_seconds_count[5m]))`,
  and the same with `status=~"5.."`; latency from `histogram_quantile` over the `_bucket` series.
- Dependencies: the same on `http_client_request_duration_seconds` by `target`.
- Saturation: `db_client_connection_count{state="used"} / db_client_connection_max`,
  `tokio_runtime_global_queue_depth`, `process_resident_memory_bytes`.
- Which commit runs where: `build_info` by `job`, `colour` and `commit`.
- Blue and green: `colour` tells them apart; during a deploy both colours report.
