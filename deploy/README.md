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

- Templates: `rust/<unit>.toml` in the private oci-config repo, one per unit, the same for every
  environment (with the runbook, `rust/RUNBOOK.md`, kept out of this public repo). Each
  value that differs by environment is a placeholder (a quoted name in angle brackets):
  `env`, `urls:<unit>` (the unit's discovery address, `http://<unit>:<port>`), `db.host:<schema>` and the rest of the database coordinates, and Java settings
  by key (`security.subdomain.endings`, `ui.cdnHostName`, ...).
- `lighthouse render <oci-config-dir> <dev|stage|prod> <out-dir>` (target/release/lighthouse)
  fills them from the Java settings in oci-config (Spring Cloud Config's precedence: `<service>-oci<env>.yml`,
  `application-oci<env>.yml`, profile sections, `<service>.yml`, `application.yml`) and writes
  `<out-dir>/<unit>.toml` for the 15 units plus `<out-dir>/rust-units.env` (TOMLs 0644, the env file 0600). It
  prints only key names: what it filled, what fell back to Java's own default, what is missing
  (exit 1). It writes byte for byte what the retired tools/render_config.py wrote.
- `rust-units.env` holds the secrets: `MODLIX__REDIS__URL`, `MODLIX__JWT__KEY`, `MODLIX__MQ__URI`,
  `MODLIX__SMS__TWO_FACTOR_API_KEY`, `MODLIX__STORAGE__*`, `MODLIX__SHELL__ANALYTICS_ENGINE_SECRET`,
  `MODLIX__EDITOR__APPLE_*`, and the values that differ per unit (`SECURITY_DB_PASSWORD`,
  `CORE_DB_PASSWORD`, `FILES_DB_PASSWORD`, `NOTIFICATION_DB_PASSWORD`, `CORE_MONGO_URI`,
  `UI_MONGO_URI`), which the compose file maps to each unit's `MODLIX__DATABASE__PASSWORD` /
  `MODLIX__MONGO__URI`. Every unit gets the whole file (as every Java service got every
  password from config-server).
- On the host: `/etc/modlix/<unit>.toml` (no secrets; readable by the image's user, uid 65532)
  and `/etc/modlix/rust-units.env` (root only; docker reads it):
  `sudo install -o root -g 65532 -m 0640 <out-dir>/*.toml /etc/modlix/` and
  `sudo install -o root -g root -m 0600 <out-dir>/rust-units.env /etc/modlix/`.
- Anything in a TOML can be overridden by environment (`MODLIX__SERVER__PORT=...`).
- ai and ssr: the same run writes `ai.env` and `ssr.env` (0600; in prod also `ssr-in.env` for the
  India nodes): every value nocode-ai and ssr-server read from config-server, under the variable
  each app reads instead (`CONFIG_SERVER_ENABLED=false` in both, `EUREKA_ENABLED=false` in
  ai.env; the gateway, security and files URLs become `http://gateway:8080`). Installed like
  rust-units.env: `sudo install -o root -g root -m 0600 <out-dir>/ai.env <out-dir>/ssr.env /etc/modlix/`.

## Layout on each host

```
/home/opc/rust/composer/docker-compose.yml   oci-config: scripts/<env>/rust/composer/docker-compose.yml
/home/opc/rust/scripts/keepup-rust.sh        oci-config: scripts/<env>/rust/scripts/keepup-rust.sh
/home/opc/rust/scripts/environment           one word: dev, stage or prod
/etc/modlix/<unit>.toml, rust-units.env      lighthouse render
/etc/modlix/ai.env, ssr.env                  lighthouse render
```

The Java side stays where it is and is not edited: `/home/opc/composer/servers` and
`/home/opc/scripts/keepup.sh`, the rollback (`keepup-rust.sh start-java`). Nothing runs from them
after the switch.

- **Blue-green.** Every unit runs as `<unit>-blue` / `<unit>-green` (prod adds `-blue-2` /
  `-green-2` for core-exec, core-editor, core-events, ui-engine, ui-shell, ui-editor, files-serve,
  files-manage), host ports blue 81NN, green 91NN, blue-2 83NN, green-2 93NN.
- **Discovery.** Every container of a unit carries the unit's name as a network alias on
  `servers_default` (`security-auth`, `core-exec`, ..., and `gateway` for gateway-rust), and
  Docker's DNS answers that name with the containers that are running. So every upstream and
  gateway pool is one address, `http://<unit>:<port>`, the same in every environment; a deploy
  changes no config, and the stopped colour simply drops out of the answer. No Java name is
  reused. (Across several hosts this would need an overlay network or a registry; every
  environment is one host today.) `keepup-rust.sh deploy <unit> <image>` pulls the image,
  tags it `<env>-<unit>:latest`, starts the stopped colour, waits for `/readyz` on its host port,
  waits 6 s more, then stops and removes the old colour (or removes the new one and keeps the old
  if it never gets ready). gateway-rust is a singleton on 8080, like gateway-server; ai and ssr
  reach it as `http://gateway:8080` (their env files).
- **core-scheduler** may overlap with itself during a deploy: each tick is claimed by a unique
  insert into `schedule_run` and each one-off by an atomic, leased claim on `scheduled_event`, so
  only one instance publishes it, and nothing is claimed before the unique indexes exist. It runs
  one instance per colour everywhere.
- **ai and ssr.** nocode-ai and ssr-server (nocode-ui) run from the Rust compose as `ai-blue` /
  `ai-green` (alias `ai`, host ports 5001 / 6001) and `ssr-blue` / `ssr-green` (alias `ssr`, 3080 /
  3081; prod adds `ssr-blue-2` / `ssr-green-2` on 3280 / 3281): the images their CI pushes
  (`<env>-ai-server`, `<env>-ssr-server`) and the ports, healthchecks and volumes of the Java
  compose, so nginx's `ssr` upstream needs no change. Ready when `/health` says UP (ai) or healthy
  (ssr). Their CI deploys with `keepup-rust.sh --env <env> deploy ai|ssr <image>`.
- **The network.** The Rust compose joins `servers_default` (external; the Java compose made it and
  stop-java leaves it); the gateway's `ai` pool is `http://ai:5001`.
- **Health checks.** The image's `/app healthcheck <port>` (explicit port: the gateway's default
  is 8180). The ui binaries do not handle `healthcheck` yet (it starts a second server), so the
  compose files switch it off for ui-*; keepup-rust checks `/readyz` itself either way (ai and
  ssr: `/health`).

## Cutover: the Java stack stops, then the Rust stack starts (decided 2026-10-17)

No environment runs Java and Rust side by side. Per environment (dev and stage first, prod
later):

1. **Before the day.**
   - The last Java release has run its Flyway migrations; `table_definition_cache` raised (gate below).
   - Images: every unit as `<env>-<unit>:<tag>` and `:latest` in OCIR (the repositories exist).
     The ui images need the `healthcheck` fix first if their compose healthcheck is to come back.
   - Render: `target/release/lighthouse render ../oci-config <env> <out-dir>` (exit 0, nothing REQUIRED
     missing), copy the 18 files (15 TOMLs, rust-units.env, ai.env, ssr.env) to the host, install
     them as above, delete the local copy.
   - Copy the compose file, `keepup-rust.sh` and an `environment` file into `/home/opc/rust`;
     pre-pull: `sudo docker compose --project-directory /home/opc/rust/composer --env-file
     /etc/modlix/rust-units.env pull`.
   - Confirm the Java core JVM's locale and zone (the compose files set `KIRUN_LOCALE=en_US`,
     `TZ=UTC` on the core units; the command is in their comment).
   - If an OCI load balancer health check probes `:8080/actuator/health`, move it to `/readyz`:
     gateway-rust has no actuator (the path falls through to ui-shell).
2. **Stop Java.**
   - Turn off the environment's Java CI deploy jobs (nocode-saas workflows): a deploy would start
     its Java service again.
   - Comment out the Java keepup cron line (it restarts every Java service that is down;
     `stop-java` and `start-all` refuse while it is on).
   - `keepup-rust.sh stop-java`: stops and removes config-server, eureka-server, gateway-server,
     every core/ui/files/multi/security/entity-processor/message/notification/worker container and
     the old ai-server-* and ssr-server-* by name with `docker compose stop` and `rm -f`, never
     `down`. RabbitMQ, Redis, MySQL and Mongo are untouched. Prod's India ssr nodes must run from
     their env file first (oci-config `rust/RUNBOOK.md`).
3. **Start Rust.** `keepup-rust.sh start-all` (blue of every unit, gateway-rust, then ai and ssr;
   core-events and notification consume whatever waits in `events1..3` and `notifications1..3`),
   then `keepup-rust.sh status`.
4. **Cron.** `keepup-rust.sh --env <env> health` on the Java line's schedule (root's crontab,
   every minute, logging to `/var/log/keepup.log` as the Java line and the CI deploys do). It keeps one ready colour of every unit, of ai and of ssr,
   takes over RabbitMQ from the Java keepup, and the weekly image prune.
5. **Scheduling.** core-scheduler takes over from the worker; apply the `platform` transport
   (tools/platform_seed/platform_SYSTEM.cmodl) with Kiran's go.
6. **Check.** `keepup-rust.sh status`, `curl localhost:8080/readyz`,
   `curl localhost:8080/metrics | grep gateway_pool_healthy`, a sign-in (tokens Java issued stay
   valid: the JWTs are the same), a page load through ssr, a server function, a file download and
   an upload, an app transport, an `/api/ai` call.
7. **Rollback.** `keepup-rust.sh start-java` stops and removes every Rust container (ai and ssr
   too), then starts config-server, eureka-server, gateway-server and the blue colour of every
   Java app service, ai-server and ssr-server (they read config-server again, which oci-config
   still points at gateway-server); put the Java cron line back and the Java CI jobs on, and the
   ai and ssr CI back on the Java keepup.

After the switch, deploys are `ssh ... bash /home/opc/rust/scripts/keepup-rust.sh deploy <unit>
<image>` (the Java workflows call `/home/opc/scripts/keepup.sh deploy`); ai and ssr too (`deploy
ai|ssr <image>`, from nocode-ai's and nocode-ui's workflows).

**What the retired services leave behind:**
- **message** is stopped: `/api/message` has no route and falls through to ui-shell (a GET gets
  the index page, where Java answered 503 with message down); every `CoreServices.Message.*`
  function answers 500; the WhatsApp bridges lose their control plane.
- **entity-processor / entity-collector**: their routes are gone the same way. Core still lists
  the apps in `core.core_remote_repositories`: for those, `repositoryFilter` and any function or
  schema name not found locally answer 500 instead of 404. Remove the rows (Kiran's call) or
  accept it.
- **worker**: core-scheduler and core-events replace it.
- **eureka** and **config-server**: gone. ai and ssr start from `/etc/modlix/ai.env` and
  `ssr.env` (`CONFIG_SERVER_ENABLED=false`, ai also `EUREKA_ENABLED=false`); a change to their
  settings in oci-config needs a new render and a redeploy (`deploy ai|ssr` with the running
  image).
- **security-admin's Let's Encrypt** is wired but off until configured. It keeps Java's ACME
  account: `security-admin acme-rollover --account <letsencrypt.login> --key-file <letsencrypt.key
  in a file>` moves that account to a new P-256 key (instant-acme signs with P-256 only; the same
  account URL, so pending orders stay bound) and prints its credentials JSON (a secret). It goes in
  `<env>/units/security-admin.toml` of oci-config-rust as `[letsencrypt] credentials`. After the
  rollover the old key no longer works, so Java's acme4j can no longer issue: run it when prod
  moves to Rust. Without the credentials, certificate requests answer `lets_encrypt_credentials`.
  **Cloudflare custom hostnames** are ported but stay off (no `[cloudflare] api_token`/`zone_id`):
  the load balancers take certificates from `ssl/internal/certificates`, not from Cloudflare.
- **Flyway**: the Java services ran their schema migrations on start; nothing does now. A
  migration runner is needed before the first schema change after cutover.

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
  (`[security] auth_upstream`, `internal_upstream`, `upstream`). `lighthouse render` fills the
  app code suffix, subdomain endings, JWT expiries, the JWT key and the MQ URI; Razorpay keys come
  from the database; Let's Encrypt needs its credentials added (above). Keep
  `[billing] serve_wallet_adjust = false` unless the owner decides otherwise.
- **ui (engine + shell + editor)**: ready; Java ui retires. The gateway splits the ui three
  ways: engine GETs (and personalization) to ui-engine, the editor controllers
  (`/api/ui/applications`, `pages`, `styles`, `themes`, `functions`, `schemas`, `filler`,
  `publish`, `uripaths`, `transports`, `versions`, `DELETE /api/ui`) to ui-editor, everything
  else to ui-shell. Rust multi calls ui-editor directly. The only Java caller of ui (worker's
  transport cleanup) retires with worker. `lighthouse render` fills ui-shell's and ui-editor's
  `ui.*` settings from the Java ui config.
- **notification**: ready. The Java notification containers stop with the rest of Java (both
  would consume `notifications1..3`); notification-blue/green (port 8114) run one at a time, as
  Java's did. Production queues may hold a backlog: Rust will process it (and send its
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
  for bound queries to fall back on. At scale (Kiran's plan: a MySQL proxy in front of
  several backends, each holding part of the tenants' tables), set the cache on each backend
  above that backend's own table count, and make sure the proxy passes server-side prepared
  statements (COM_STMT_PREPARE / COM_STMT_EXECUTE) through.
- **KIRun locale and zone (core units).** kirun-rust now answers as kirun-java (K1-K6 resolved
  2026-10-17), including dates, which follow the process locale and zone as the JVM's do. Set
  `KIRUN_LOCALE` and `TZ` on core-exec, core-editor, core-events and core-scheduler to the Java
  core JVM's values (the compose files set en_US / UTC, to confirm on the host). Locally they run with
  `KIRUN_LOCALE=en_IN` (the local JVM's; tools/run-local.sh sets it). Core builds against
  kirun 2.0.0 from crates.io (released 2026-10-17).
- **Java drift**: before cutover, rerun the drift list in the migration PROGRESS.md against
  `git log` of the ported Java modules; Java keeps changing during the port.
- Check: load a real page through the gateway with the console open (the leadzump home page on
  `leadzump.local.modlix.com:<gateway port>` locally) and compare its network log with Java's.

## Monitoring changes needed (not made)

- **Prometheus**: no static targets. Alloy on each app host discovers the units from the host's
  Lighthouse pair and scrapes `/metrics` (oci-config, `scripts/monitoring/alloy/config-rust-units.alloy`,
  appended by `rollout.sh`); the Java `/actuator/prometheus` jobs are retired per environment at
  its switch (`scripts/monitoring/prometheus/retire-java-actuator-jobs.yml`). Every family and
  label is in [METRICS.md](METRICS.md). The Rust request metric is
  `http_server_request_duration_seconds`; the Java panels use `http_server_requests_seconds`, so
  dashboards need a panel per runtime (or a recording rule) during the migration.
- **Alloy**: the Rust units log JSON to stdout, not to `/var/log/apps/*.log`. Add a
  `loki.source.docker` for the `modlix-rust` compose project's containers, with `level`, `service`
  (`target` is the Rust module) and `trace_id` from the JSON.
- **Tempo** (optional): set `telemetry.otlp_endpoint = "http://alloy:4318"` and an
  `otelcol.receiver.otlp` in Alloy forwarding to Tempo; gateway-rust then starts a trace per request
  and every Rust unit continues it.
- **keepup**: done: keepup-rust.sh (oci-config, scripts/<env>/rust/scripts/) checks `/readyz` on each instance's host
  port.
- **Grafana alerts** that filter on `service="files"` or the Java gateway need updating; list them
  before cutover.
