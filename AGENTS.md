# Working in nocode-saas-rust

Rust replacements for the Java services in `../nocode-saas`, one unit at a time, behaviour-compatible
with the Java service each replaces. Read this before changing anything.

## Hard rules

- **Never** `git commit`, `git push`, `git stash`, open PRs, or touch git state. Leave changes in the
  working tree. The owner reviews and commits.
- **Never** deploy, SSH, or touch dev/stage/prod. Everything runs against the local stack.
- **Never** write Modlix definitions (pages, functions, apps, storages...) straight into MongoDB, and
  never write rows into the per-tenant `<CLIENT>_<app>` databases directly. Through an API (Java
  or Rust) on local is fine.
- Stay inside your crate. `crates/platform` is shared: change it only if your brief says so, and keep
  existing APIs working.
- Do not edit the Java code in `../nocode-saas` or anything in `../oci-config`.
- **Do not start sub-agents or background workers** without the coordinator's go. The owner caps
  the whole session at 3-4 agents (usage limits), and parallel live-database suites starve the
  local MySQL (151 connections, ~80-110 already in use by the stack). Do the work yourself, one
  live suite at a time.

## Secrets in config files

Never print `config/local.toml` or oci-config values unfiltered: they hold real
secrets. Key names only.

## Scratch files

Keep scratch files (probe scripts, captured outputs) under `target/scratch/<your lane>/`
(git-ignored). Never write them into another agent's lane.

## Disk

The machine's disk is nearly full (it ran out on 2026-10-15 and broke builds and the local
stack). Build in the shared `target/debug` for tests; use a separate target dir only for coverage
(`CARGO_LLVM_COV_TARGET_DIR=target/cov-<crate>`, with `CARGO_INCREMENTAL=0`), and delete it as
soon as the number is recorded. Never keep extra `target/t-*` copies or whole-workspace copies
around after use. Check `df -h /System/Volumes/Data` before a big build.

## Layout

```
crates/platform   shared: config, telemetry, health, app runner, http helpers, errors, security
                  client, cache eviction, upstream resolution, mysql pool, Java hashing, eureka shim
crates/gateway    gateway-rust
crates/files      files-serve + files-manage (bins in src/bin, everything else in the library)
crates/ui         ui units
crates/core       core units
config/           local TOML per binary (config/<binary>.toml), ai.toml and ssr.toml; every password and
                  key in config/local.toml (git-ignored).
                  The local Lighthouse serves both to the units (config/lighthouse.toml, env local)
tools/            run-local.sh, restart-local.sh, local-env.py, smoke.py, the platform app seed
deploy/           Dockerfiles and example configs (not applied anywhere)
```

## How a unit is built

1. Read the Java code you replace end to end before writing Rust: controller, service, DAO, the
   commons base classes it inherits, its config.
2. Port the behaviour exactly: status codes, headers, JSON field names and shapes, error bodies,
   cache names, SQL meaning. When Java has a bug, either keep it (and say so in a comment) or fix it
   and add it to the crate's `DIFFERENCES.md` with the reason. Never change behaviour silently.
3. Use the platform pieces:
   - `platform::config::load::<YourConfig>("<binary>")`, struct with `#[serde(default)]` sections,
     reusing `ServerConfig`, `TelemetryConfig`, `EurekaConfig`, `RedisConfig`, `SecurityConfig`,
     `MySqlConfig`.
   - `platform::telemetry::init`, `platform::health::Health` (add readiness checks),
     `platform::app::Service { .. }.run(router)`.
   - Responses carry their Spring route pattern via `platform::http::with_route(resp, "/api/...")`
     so metrics label by route.
   - Errors: `platform::error::{AppError, AppResult}` (Java's `GenericException` JSON shape).
   - Caller identity: `platform::security::{CallerContext, SecurityClient}`.
   - Cache: `platform::cache::CacheService` with prefix `cmn` (the effective Java prefix for every
     service: `application-<profile>.yml` outranks the per-service yml), so Java evictions reach
     Rust and Rust evictions reach Java (`evict_all_everywhere`). Check what Java really publishes
     on `evictionChannel` before relying on a cache name.
   - Other services: `platform::upstream::Upstream` (`eureka:<APP>` or base URLs).
4. Unit tests for every non-trivial rule, using values observed from the running Java service.
5. Java is retired (2026-10-19): the parity scripts that compared Rust with it are gone. A
   behaviour change against what Java did still gets its `DIFFERENCES.md` entry.

## The local stack

| What | Where |
|---|---|
| security / ui / files / core (Java) | `localhost:8001` / `8002` / `8003` / `8005` |
| Spring gateway | `localhost:8080` |
| config server / eureka | `localhost:8888` / `localhost:9999/eureka/` |
| MySQL | `127.0.0.1:3306`, `root` / `[units.database] password` in config/local.toml |
| MongoDB | `mongodb://localhost:27017`, no auth (`ui`, `core` databases) |
| Redis | `[units.redis] url` in `config/local.toml` |
| Java config values | `curl -s localhost:8888/<service>/default` (JSON; do not print secrets) |

Signing in locally (allowed on local, any time): every local user's password is `Pass@1234`.
`Authorization: Basic base64("142:Pass@1234")` with headers `clientCode: SYSTEM`,
`appCode: appbuilder` is the SYSTEM user 142. For a bearer token,
`POST localhost:8080/api/security/authenticate` with `{"userName":"kiran@modlix.com","userId":142,
"password":"Pass@1234","rememberMe":false}` and the same headers (a bare `"userName":"142"`
answers "No registration available"; tools/platform_common.py signs in this way). Never try any
other password.

Run a unit: `cargo build --release -p <crate> && tools/run-local.sh <binary> --release`. The units
take their configuration from the local Lighthouse pair (8761, 8762), so start it first:
`tools/run-local.sh lighthouse --release`, and for the second instance the same with
`MODLIX__SERVER__PORT=8762 MODLIX__REGISTRY__SELF_URL=http://localhost:8762`. Lighthouse serves
each unit its config/<unit>.toml with config/local.toml's `[units.*]` merged in, and re-reads them every 5 s;
a changed file shows as a new version on the dashboard (http://localhost:8761), and the unit picks
it up on its next restart. `LIGHTHOUSE=off tools/run-local.sh <binary>` runs a unit from the file
and env the old way. The local ai and ssr read their Spring settings from Lighthouse too
(`/ai/default`, `/ssr/default`): config/ai.toml and config/ssr.toml with local.toml's `[ai]` and `[ssr]`.
The gated live tests read the secrets from their environment: `eval "$(tools/local-env.py)"` first.
Rust units listen on 81xx ports (files-serve 8103, files-manage 8104, ui-engine 8102, ui-shell
8106, ui-editor 8107, core-exec 8105, core-scheduler 8108, core-events 8109, core-editor 8111,
security-auth 8101, security-internal 8112, security-admin 8113, notification 8114, multi 8110,
gateway 8080 from config/gateway-rust-allrust.toml).

## Style

- Match the existing code: doc comments explain why, in plain sentences; no commented-out code.
- `anyhow` inside, `AppError` at the HTTP edge. No `unwrap()` on anything that can fail at runtime.
- Keep functions small enough to read; port Java structure only where it helps the reader.
