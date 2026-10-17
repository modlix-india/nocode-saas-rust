# gateway-rust compared with the Spring Cloud Gateway

Measured against `nocode-saas/gateway` on the local stack with `tools/parity_gateway.py` (28/28
same: ui, files, security, core, ai, uploads, ranges, HEAD, CORS, codes in the URL, draft
stripping).

## Same on purpose (reproduced, including quirks)

- Path: the codes prefix before `/api/` is dropped and never read as codes; codes come from
  the URL only for `/page/` and `/manifest/` paths (`/<appCode>/<clientCode>/page/...`).
  A trailing `/` is removed.
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

- **Load balancing** is the gateway's own: round robin over instances that pass active health
  checks (every 5 s, configurable path), with an instance ejected on a connect failure. Spring
  used Eureka's list as is. A pool whose instances all fail still routes to them (a wrong
  health path must not black-hole a service).
- **Retry**: a request without a body is retried once on another instance when the connection
  is refused. Spring did not retry.
- **Errors** are the platform's coded body (no stack trace; `code`, a plain `message` in the
  request's language, `action`, the pool and cause in `debugMessage`; catalogue
  `messages/en.toml`, codes `GW.*`): `GW.SERVICE_STARTING` (503, no instance registered or
  healthy), `GW.SERVICE_UNAVAILABLE` (503, every attempt refused), `GW.SERVICE_TIMEOUT` (504, no
  answer within the route timeout), `GW.SERVICE_FAILED` (502, the connection broke),
  `GW.HOST_UNRESOLVED` (502, host resolution failed), `GW.NO_ROUTE` (404). Spring answered
  500/503 with its own error body. A service's own errors pass through untouched. The CORS
  preflight refusal stays an empty 403: browsers never show a preflight's body.
- **No Eureka needed**: pools are static addresses (compose container names, later Kubernetes
  Services) or `eureka:<APP>` during the migration.
- `X-Forwarded-Prefix` is not added (Spring adds it only for its discovery-locator routes,
  which nothing uses).
- Metrics are `http_server_request_duration_seconds{route=<route id>}` plus
  `gateway_pool_healthy_instances{pool}`; Spring's `http_server_requests_seconds` is not kept.

## Measured locally (2026-10-15, same machine, same upstream)

| | Spring gateway | gateway-rust |
|---|---|---|
| 3000 requests, 50 concurrent, static file through files | 5,945 rps, p50 8 ms, p99 20 ms | 10,381 rps, p50 4 ms, p99 13 ms |
| 28 parity requests, total | 448 ms | 447 ms |
