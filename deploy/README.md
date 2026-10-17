# Deploying the Rust units

Nothing here is applied anywhere. It is what the cutover needs, for review.

## Images

One image per binary, from `deploy/Dockerfile`:

```
docker build -f deploy/Dockerfile --build-arg BIN=gateway-rust -t prod-gateway-rust .
docker build -f deploy/Dockerfile --build-arg BIN=files-serve  -t prod-files-serve .
docker build -f deploy/Dockerfile --build-arg BIN=files-manage -t prod-files-manage .
```

Distroless (`cc-debian12:nonroot`): no shell, no curl. The container health check is the binary
itself: `/app healthcheck` asks `/readyz` and exits 0 or 1.

## Configuration

- `/etc/modlix/<binary>.toml` on the host, mounted read-only. Examples: `deploy/config/*.production.toml`.
- Secrets in `/etc/modlix/rust-units.env` (outside git), as `MODLIX__SECTION__KEY` variables.
- Anything in the TOML can be overridden by environment (`MODLIX__SERVER__PORT=...`).

## Cutover (all at once)

1. Push the images (CI), copy the TOMLs and the env file to the host.
2. `docker compose up -d files-serve-1 files-serve-2 files-manage-1 files-manage-2`.
   files-manage registers in Eureka as `FILES`; Java Feign callers start using it alongside the
   Java files containers.
3. Stop the Java files containers (`files-server-*`). Every `FILES` Feign call now lands on
   files-manage.
4. Stop `gateway-server`, `docker compose up -d gateway-rust` (same port 8080). nginx needs no
   change.
5. Check: `curl localhost:8080/readyz`, `curl localhost:8080/metrics | grep gateway_pool_healthy`,
   a page load, a file download, an upload.

## Cutover gates

A unit takes traffic only when everything it answers for is ported; a partial unit behind the
gateway breaks pages in ways no single endpoint test shows.

- **core (exec + editor + scheduler + events)**: ready; Java core retires once the scheduling
  cutover below is done. The gateway sends function execution, data, spreadsheet, connection
  oauth/internal, repositoryFind/Filter, eventRuns and events/internal to core-exec, and the
  editor routes plus the `/api/core` catch-all to core-editor.
- **Scheduling (core-scheduler + core-events; worker retires)**: ready apart from core-editor
  (core-events' `[core] upstream` points at core-editor for the platform jobs' internal calls).
  Order (crates/core/NEEDS.md): stop the Java worker; set `core.scheduler.enabled=false` on Java
  core; take Java core off `events1..3`; start core-scheduler and core-events; then apply the
  `platform` transport (tools/platform_seed/platform_SYSTEM.cmodl) with Kiran's go.
- **security (auth + internal + admin)**: ready; Java security retires. The gateway sends
  AuthenticationController's routes to security-auth, the routes the units' classifier marks
  internal (`classifier = "security-internal"`) to security-internal, and everything else under
  `/api/security` to security-admin; every Rust unit splits its own security calls the same way
  (`[security] auth_upstream`, `internal_upstream`, `upstream`). Fill the placeholders in
  `security-*.production.toml` (app code suffix, subdomain endings, the JWT key, the MQ URI,
  Razorpay, Let's Encrypt and Cloudflare settings) from the production Java config. Keep
  `[billing] serve_wallet_adjust = false` unless the owner decides otherwise.
- **ui (engine + shell + editor)**: ready; Java ui retires. The gateway splits the ui three
  ways: engine GETs (and personalization) to ui-engine, the editor controllers
  (`/api/ui/applications`, `pages`, `styles`, `themes`, `functions`, `schemas`, `filler`,
  `publish`, `uripaths`, `transports`, `versions`, `DELETE /api/ui`) to ui-editor, everything
  else to ui-shell. Rust multi calls ui-editor directly. The only Java caller of ui (worker's
  transport cleanup) retires with worker. Fill the placeholders in `ui-shell.production.toml`
  and `ui-editor.production.toml` from the production Java ui config first.
- **notification**: ready. Stop the Java notification containers first (both would consume
  `notifications1..3`), then start notification-1/2 (port 8114); the gateway's notification pool
  points at them. Production queues may hold a backlog: Rust will process it (and send its
  email) on start. Known limit, same as Java: with several instances a notification reaches only
  the SSE streams open on the instance that consumed it (crates/notification DIFFERENCES N1 has
  the Redis fan-out fix, not built).
- **MySQL `table_definition_cache` (must check before cutover).** The Rust units use prepared
  statements (sqlx's binary protocol); Java's jOOQ does not. When the server has more tables than
  `table_definition_cache` holds, MySQL evicts definitions and prepared statements fail with
  error 1615 ("Prepared statement needs to be re-prepared"). Locally (1,453 schemas, 4,940 tables)
  every Rust sign-in failed at the default 2000; `SET GLOBAL table_definition_cache = 10000`
  fixed it (not persisted: lost on a MySQL restart). On every environment, compare
  `SHOW VARIABLES LIKE 'table_definition_cache'` with
  `SELECT COUNT(*) FROM information_schema.tables` and set the cache above the table count
  before the Rust units take traffic. On OCI's MySQL HeatWave the variable is a user variable of
  the DB system's configuration (400 to 524,288; the default `AUTOSIZED` comes to 2000 with
  `table_open_cache` at 4000): copy the current configuration, set `table_definition_cache` in
  the copy, and edit the DB system to use it. Elsewhere, my.cnf. A throwaway MySQL 8.4 with 1,500
  tables and a cache of 400 did not fail (MySQL re-prepares on its own), so the trigger is
  narrower than "more tables than the cache"; the local failure had 2,056 definitions open
  against 2,000. Raising the cache is still the fix that worked; sqlx has no text-protocol mode
  for bound queries to fall back on.
- **KIRun locale and zone (core units).** kirun-rust now answers as kirun-java (K1-K6 resolved
  2026-10-17), including dates, which follow the process locale and zone as the JVM's do. Set
  `KIRUN_LOCALE` and `TZ` on core-exec, core-editor, core-events and core-scheduler to the Java
  core JVM's values (placeholders in deploy/compose/rust-units.yml). Locally they run with
  `KIRUN_LOCALE=en_IN` (the local JVM's). The kirun change is unreleased: it lives in the
  nocode-kirun working tree and core builds against it by path; a crate release is the owner's.
- **Java drift**: before cutover, rerun the drift list in the migration PROGRESS.md against
  `git log` of the ported Java modules; Java keeps changing during the port.
- Check: load a real page through the gateway with the console open (the leadzump home page on
  `leadzump.local.modlix.com:<gateway port>` locally) and compare its network log with Java's.

## Monitoring changes needed (not made)

- **Prometheus** (jumphost, static targets today): add `gateway-rust:8080`, `files-serve-1/2`,
  `files-manage-1/2` with `metrics_path: /metrics`. The Rust metric is
  `http_server_request_duration_seconds{service,instance,environment,method,route,status}`; the
  Java panels use `http_server_requests_seconds`, so dashboards need a panel per runtime (or a
  recording rule) during the migration.
- **Alloy**: the Rust units log JSON to stdout, not to `/var/log/apps/*.log`. Add a
  `loki.source.docker` for the `gateway-rust`, `files-*` containers, with `level`, `service`
  (`target` is the Rust module) and `trace_id` from the JSON.
- **Tempo** (optional): set `telemetry.otlp_endpoint = "http://alloy:4318"` and an
  `otelcol.receiver.otlp` in Alloy forwarding to Tempo; gateway-rust then starts a trace per request
  and every Rust unit continues it.
- **keepup.sh**: health checks for the Rust units are `/readyz` (or `docker inspect` health,
  since the image has its own HEALTHCHECK).
- **Grafana alerts** that filter on `service="files"` or the Java gateway need updating; list them
  before cutover.
