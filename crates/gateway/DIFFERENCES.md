# gateway-rust compared with the Spring Cloud Gateway

Measured against `nocode-saas/gateway` on the local stack with `tools/parity_gateway.py` (28/28
same: ui, files, security, core, ai, uploads, ranges, HEAD, CORS, codes in the URL, draft
stripping).

## Same on purpose (reproduced, including quirks)

- Path: the codes prefix before `/api/` is dropped from the forwarded path; codes come from
  the URL, unchecked, for `/page/` and `/manifest/` paths (`/<appCode>/<clientCode>/page/...`,
  also `/<appCode>/<clientCode>/page/api/...`). A trailing `/` is removed. Codes in front of
  `/api/` with no `/page/` before it are the one difference (below).
- Host resolution: `getClientNAppCodeNType(scheme, host, port)`, with the port `-1` when the
  Host header has none, exactly as `URI.getPort()` reports it to the Java filter.
- `appCode` / `clientCode` headers filled in only when the caller sent none (caller-overridable,
  as today). `x-draft` always stripped, set only for a DRAFT surface whose codes match.
- Draft token hosts (`t-<32 hex>`): trusted for the sooner of 60 s and the token's expiry,
  denial cached for 60 s, any failure reads as LIVE.
- Forwarded headers: `Host` becomes the instance's address; `X-Forwarded-*` appended with a
  comma; `Forwarded` added.
- Every CORS preflight (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) is refused
  with an empty 403 at the edge, as the Spring gateway does (it has no CORS configuration).
  Passing preflights to the services would let ui's permissive CORS open cross-origin calls
  that are refused today.
- SSE: requests accepting `text/event-stream` (or under `/api/ai/`) get unbuffered responses
  with `Cache-Control: no-cache, no-store, must-revalidate` and `X-Accel-Buffering: no`.

## Different on purpose

- **URL codes in front of `/api/`** (Kiran, 2026-10-22; `path.rs` `split`, `resolve.rs`). Java
  (since 2022) never read the codes in `/<appCode>/<clientCode>/api/...`: the host decided. Now
  they count when they name a real app and client: the client owns the app or has access to it,
  as security's `GET /api/security/applications/internal/hasReadAccess?appCode=&clientCode=`
  answers (an unknown app or client is `false`). Otherwise the host decides exactly as before,
  so a relative URL's junk prefix (`/x/y/api/ui/application`) still resolves by host. Codes that
  can not be real (one segment, a blank segment, a character other than letters, digits, `_`
  and `-`, more than 64) are not asked about. The answer is cached in the gateway under
  security's own cache name and key (`appReadAccess`, `<appCode>:<clientCode>`, true and false
  alike, for the `[redis]` TTL), so security's evictions when an app's access changes, or an
  app is created or deleted, clear it here too; a failed lookup is not cached and resolves by
  host. Draft token hosts keep Java's rule (only codes after a `/page/`). A caller's own
  `clientCode` / `appCode` headers still win, and internal calls naming their codes still pass
  straight through. This is what makes a tenant's webhook address
  `https://<host>/<appCode>/<CLIENTCODE>/api/webhooks/<provider>` (ui DIFFERENCES.md item 39)
  run for that tenant.

- **Routes with a rewrite and fixed codes** (2026-10-23, website lead intake; `routes.rs`,
  `proxy.rs` `upstream_headers`). A route may set `rewrite` (its prefix in the forwarded path is
  replaced, what follows is kept), `app_code` + `client_code` (both or neither) and `anonymous`.
  With codes, the request goes out with exactly those `appCode` / `clientCode` headers, over
  any the caller sent, the host is not resolved (no security call), `x-draft` is dropped, and
  `X-Forwarded-*` / `Forwarded` are added as on any route, so the service still sees the site's
  host. `anonymous` drops `Authorization`. Spring had no such route: every live real-estate site
  posts its form to its own domain at `/api/entity/processor/entry/website` (or
  `/api/entity/collector/entry/website`), which Spring sent to entity-processor / collector
  whatever the host. Those services are retired; these routes send the same requests to
  leadzumptwo's intake URIPath (`/api/open/intake/website`, app leadzumptwo, SYSTEM), which finds
  the tenant from the host as entity-processor did. A route config that sets one code alone,
  rewrites outside `/api/` or rewrites `/` is refused at startup. Without these keys a route is
  exactly as before. Tests: `routes.rs` `rewrites_and_fixed_codes`, `tests/proxy.rs`
  `a_fixed_codes_route_rewrites_and_serves_every_host_anonymously`.
- **Load balancing** is the gateway's own: round robin over instances that pass active health
  checks (every 5 s, configurable path), with an instance ejected on a connect failure. Spring
  used the registry protocol's list as is. A pool whose instances all fail still routes to them (a wrong
  health path must not black-hole a service).
- **Outlier ejection**: an instance that gives 5 gateway failures in a row (502/503/504, a
  broken connection, a timeout) is ejected for 10 s times the number of times it has been
  ejected, at most 120 s, and comes back at the first passing health check after that (one is
  run as the time runs out). At most 50% of a pool is ejected this way; a pool of one never is.
  Spring had none.
- **Retry**: at most one retry, always on another instance. A request without a body (any
  method) is retried when the connection could not be opened, since nothing reached the
  instance (before 2026-10-19 only GET, HEAD, OPTIONS and DELETE were). A GET, HEAD, OPTIONS,
  PUT or DELETE without a body answered 502, 503 or 504 is retried after 25 to 50 ms, within a
  retry budget per pool (20% of its requests over 10 s, or 3 a second when traffic is light).
  A timeout is never retried, nor is a POST or PATCH that was sent, nor anything with a body.
  If the retry gets no answer at all, the first instance's answer is passed on. Spring did not
  retry.
- **Circuit breaker per pool**: over a 10 s window (1 s buckets), 20 or more requests with 50%
  or more failing (connect failure, timeout, broken connection, or 502/503/504 as the final
  answer after any retry) open it. While open, the pool's requests get `GW.SERVICE_UNAVAILABLE`
  (503) at once, with "circuit breaker is open" in `debugMessage`. After 5 s, 3 trial requests
  go through: all passing closes it, one failing opens it again for twice as long, up to 60 s.
  Spring had none.
- All of the above is per pool in the TOML (`[pools.<name>.outlier]`, `.retry`, `.breaker`);
  the numbers here are the defaults.
- **Unit-to-unit calls** (preparation, nothing points at the gateway yet): a request on an
  internal path (one containing `/internal`, which nginx refuses from outside) that already
  carries `clientCode` and `appCode` skips host resolution and passes through as if it went
  straight to the unit: its codes, `x-draft` and `X-Forwarded-*` / `Forwarded` headers are left
  as the caller sent them (only `Host` and hop-by-hop headers change). Spring resolved the host
  and appended its hop for these too; through it, a caller's `x-draft` was dropped and its
  `X-Forwarded-Host` became `<host>,<gateway host>`. ai's internal calls (which send both
  codes) now arrive like a direct call. The gateway's own security calls always go straight to
  the security units (`[security]`), never through itself.
- **Errors** are the platform's coded body (no stack trace; `code`, a plain `message` in the
  request's language, `action`, the pool and cause in `debugMessage`; catalogue
  `messages/en.toml`, codes `GW.*`): `GW.SERVICE_STARTING` (503, no instance registered or
  healthy), `GW.SERVICE_UNAVAILABLE` (503, every attempt refused), `GW.SERVICE_TIMEOUT` (504, no
  answer within the route timeout), `GW.SERVICE_FAILED` (502, the connection broke),
  `GW.HOST_UNRESOLVED` (502, host resolution failed), `GW.NO_ROUTE` (404). Spring answered
  500/503 with its own error body. A service's own errors pass through untouched. The CORS
  preflight refusal stays an empty 403: browsers never show a preflight's body.
- **No Lighthouse needed**: pools are static addresses (compose container names, later Kubernetes
  Services) or `lighthouse:<APP>` during the migration. A `lighthouse:` pool reads the registry every
  2 s (`discovery_refresh_ms`), not every 30 s, and believes an empty list only after the
  registry has answered empty 3 times in a row.
- `X-Forwarded-Prefix` is not added (Spring adds it only for its discovery-locator routes,
  which nothing uses).
- Metrics are `http_server_request_duration_seconds{route=<route id>}` plus, per pool,
  `gateway_pool_healthy_instances`, `gateway_pool_ejected_instances`,
  `gateway_pool_ejections_total{reason=connect|5xx}`, `gateway_retries_total{reason=connect|5xx}`,
  `gateway_retry_budget_exhausted_total`, `gateway_pool_breaker_rejections_total` and
  `gateway_pool_breaker_state` (0 closed, 1 half-open, 2 open). Every series exists from the
  start at zero. Spring's `http_server_requests_seconds` is not kept.

## Measured locally (2026-10-15, same machine, same upstream)

| | Spring gateway | gateway-rust |
|---|---|---|
| 3000 requests, 50 concurrent, static file through files | 5,945 rps, p50 8 ms, p99 20 ms | 10,381 rps, p50 4 ms, p99 13 ms |
| 28 parity requests, total | 448 ms | 447 ms |
