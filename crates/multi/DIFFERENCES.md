# multi compared with the Java multi service

Measured with `tools/parity_multi.py --writes` against Java multi (8006): every read case the
same (index, search with type and query, client override, unknown app, anonymous 401, missing
header 400, create by app id, update without a definition, transport export of `appa` and of
`monkbars`, compared by zip contents), and the write round trip the same on both sides
(create a scratch app, update it with a JSON definition, soft delete, full delete).

## Different on purpose

- **`encodedModl` works.** Java base64-*encodes* the already encoded upload before reading it
  as a zip, so creating or updating an app from `encodedModl` always failed. Rust decodes it.
- **JSON is compact.** Java pretty-prints (`"key" : value`). Same content, same field order,
  same null handling (the `App` DTO leaves nulls out, maps keep them).
- **The ui and core halves of the object index are fetched concurrently** (Java one after the
  other). Same result, about half the latency.
- **Errors** carry no stack trace; a missing required header or parameter is a 400 (Java gives
  400 or 500 depending on which one is missing).
- **Error bodies are coded** (2026-10-17, the plan in ERROR_MESSAGES.md): every error multi
  raises carries a stable `code`, a `message` in plain words in the request's language, an
  `action` when there is a next step, `params` and `locale`; Java's own text goes to
  `debugMessage` (`[forbidden_create] Cannot create transport for the selected client`). Codes
  are `MULTI.*` (`messages/en.toml`) and the platform's `COMMON.*`. `tools/parity_multi.py`
  compares them by code (`tools/error_parity.py`).

  | Case | Java | Rust |
  |---|---|---|
  | not signed in | empty 401 | 401 `COMMON.SIGN_IN_REQUIRED`, or `COMMON.SIGNED_OUT` when a token or password was sent and refused |
  | export without write access | 403 "Cannot create transport for the selected client" | 403 `MULTI.TRANSPORT_EXPORT_FORBIDDEN` |
  | create without Application CREATE | 403 "Cannot create Application for the selected client" | 403 `MULTI.APP_CREATE_FORBIDDEN`, naming the permission |
  | missing header, missing `appCode`, no body, a body or value that does not read | 400 or 500 "Please try again. A server error - <id>" | 400 `COMMON.HEADER_MISSING`, `COMMON.PARAM_MISSING`, `COMMON.BODY_MISSING`, `COMMON.BODY_NOT_JSON`, `COMMON.BODY_UNREADABLE`, `COMMON.FIELD_INVALID`... naming the header, parameter or field |
  | a definition that cannot be fetched or read (`transportDefinitionURL` failing or over 50 MB, `encodedModl` not base64, neither JSON nor a `.modl` zip) | 500 "Error while creating/updating application" or "Please try again" | **400** `MULTI.DEFINITION_URL_FAILED`, `DEFINITION_TOO_LARGE`, `ENCODED_MODL_INVALID`, `DEFINITION_UNREADABLE`: the definition is the caller's input |
  | security, core or ui not reachable | 500 "Please try again" | **503** `MULTI.SERVICE_UNAVAILABLE` naming the service (504 when it did not answer in time) |
  | anything unexpected | 500 "Please try again. A server error - <id>" | 500 `COMMON.INTERNAL_ERROR` ("Something went wrong on our side. Error id <id>: give it to support.") |

- **Errors from the services multi calls.** A coded body (a Rust unit's) is passed on exactly as
  it came, status, `exceptionId` and all, so the person reads the text that service wrote and
  support finds the cause under that service's error id (Java re-wraps the `message` under a new
  id). A Java JSON body's `message` is relayed with its status, as Java does. An error with an
  empty or unreadable body reads `COMMON.SIGNED_OUT` (401), `COMMON.FORBIDDEN` (403) or
  `MULTI.SERVICE_FAILED` with the service's status (Java: the catch-all 500). The caller's
  `Accept-Language` travels with every call made on its behalf, so a passed-on message is in the
  caller's language.

- **Purge routes (new, 2026-10-26, no Java counterpart).** `DELETE /api/multi/purge/client/{code}`
  and `DELETE /api/multi/purge/application/{code}`, `dryRun` true unless `dryRun=false`. Security
  is asked first as a dry run and its refusal (409 `SEC.PURGE_REFUSED`: a client that still owns
  apps, manages clients or has invoices/payments; an app with invoices or apps depending on it)
  stops the purge before core or ui change anything. Then core (`/api/core/purge/...`: definitions
  and the `<CLIENT>_<app>` tenant databases), ui (`/api/ui/purge/...`) and security
  (`/api/security/.../purge/...`) run with the caller's `dryRun`; the answer is
  `{dryRun, security, core, ui, files}`; files (`/api/files/purge/...` on files-manage, the
  optional `[files]` upstream: without it the purge is a 503 naming files) runs after ui and
  before security, which it asks who manages the client. A client is purged only by a client
  that manages it, never by itself, and SYSTEM never; an app only by SYSTEM. Codes are letters, digits and `_` only (they go into three URLs).
  Made for the clean-slate wipe of dead test clients and empty apps on local, dev and stage. Unlike
  `DELETE /api/multi/application/{code}`, an app purge takes every client's definitions and tenant
  data, not only the caller's.

## Same on purpose

- Every route needs a signed-in caller (anonymous: a 401 without a `WWW-Authenticate` challenge,
  as Java since aca9929dd; the body is coded, see above).
- `update` has no access check of its own, as in Java; core, ui and security check access when
  the transport is applied.
- A half of the index that fails is logged and reported in `services`, not an error.
- When security finds no base client for an app, the client code in the definition is `null`,
  and the receiving services use the caller's client.
