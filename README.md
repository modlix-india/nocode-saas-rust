# nocode-saas-rust

The backend of [Modlix](https://modlix.com), a no-code platform, written in Rust.

It replaced the platform's Java services (Spring Boot, Project Reactor) in production on 2 November
2026, three weeks after the first commit, with about 17 minutes of downtime. Java is retired.

| | |
|---|---|
| Crates | 13 |
| Service binaries | 16 |
| Rust | 260k lines |
| Tests | 3,600+ |
| Stack | axum, tokio, sqlx (MySQL), MongoDB, Redis, RabbitMQ, OpenTelemetry, Prometheus |

## What's inside

| Crate | Binaries | What it does |
|---|---|---|
| `gateway` | `gateway-rust` | The edge for every API call, and the load balancer in front of the services. Replaces Spring Cloud Gateway. |
| `lighthouse` | `lighthouse` | Service registry (registry protocol, peer replication, eviction with self-preservation) and config server. Replaces Eureka and Spring Cloud Config. |
| `security` | `security-auth`, `security-internal`, `security-admin` | Sign-in, tokens and the caller's context; service-to-service routes; administration. |
| `ui` | `ui-engine`, `ui-shell`, `ui-editor` | Serves no-code apps (pages, URI paths, SSO, cache control) and the editor's create, draft, version, publish and transport paths. |
| `core` | `core-exec`, `core-events`, `core-scheduler`, `core-editor` | Executes business logic on [KIRun](https://github.com/modlix-india/nocode-kirun), plus events, scheduling and editing. |
| `files` | `files-serve`, `files-manage` | Reads, uploads, folders, zips, transforms, access paths, retention and billing for files. |
| `notification` | `notification` | In-app notifications over SSE, email and in-app sends from the queue, user preferences. |
| `multi` | `multi` | Operations across services: object index and search, transport export and import, delete. |
| `platform` | | What every service shares: config, telemetry, health, errors, security client, cache eviction, upstream resolution, MySQL pool. |
| `overridable` | | The inheritance engine: each client inherits its parent's definitions and stores only its own differences (drafts, versions, publish). |
| `appdata` | | App data storage with MongoDB and MySQL backends behind one trait, including DDL, a migration journal and drift reports. |
| `connections` | | Outbound integrations: REST (basic, OAuth2, token functions) behind a private-target guard, email, AI chat, RabbitMQ publishers. |
| `lighthouse-client` | | Registration and registry watch for every service. |

## How it was built

- **One unit at a time, behaviour-compatible.** Each service ports the Java service it replaces
  exactly: status codes, headers, JSON shapes, error bodies, cache names, SQL meaning.
- **No silent changes.** When the Rust service deliberately differs from Java, for example to fix
  a Java bug, the difference and its reason go into that crate's `DIFFERENCES.md`. There are 12 of
  them, one per crate that has differences.
- **Java and Rust side by side.** Both used the same Redis cache prefix, so an eviction on either
  side reached the other while the two ran together.
- **AI coding agents in parallel lanes.** Each agent worked on one crate under the shared rules in
  [`AGENTS.md`](AGENTS.md). Every unit was checked for parity against the live Java service before
  it went to production.

## Running locally

```bash
cargo build --release -p lighthouse
tools/run-local.sh lighthouse --release        # registry and config server first

cargo build --release -p gateway
tools/run-local.sh gateway-rust --release      # then any unit, by binary name
```

Each binary reads `config/<binary>.toml` through Lighthouse, merged with the git-ignored
`config/local.toml`, which holds every password and key. `deploy/` has the Dockerfiles: one
distroless image per binary, whose health check is the binary itself.

## Related

- [nocode-kirun](https://github.com/modlix-india/nocode-kirun): the logic runtime, in TypeScript, Java, Rust and Python
- [nocode-ui](https://github.com/modlix-india/nocode-ui): the rendering engine and visual IDE
- [nocode-saas](https://github.com/modlix-india/nocode-saas): the retired Java backend

## License

MIT
