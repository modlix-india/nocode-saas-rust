# notification compared with the Java notification service

Measured against `nocode-saas/notification` (the jar built 2026-10-13, current with nocode-saas
`3cf6ebc54`; the notification module last changed 2026-09-01) on the local stack with
`tools/parity_notification.py`: 80 cases, 73 SAME, 7 EXPECTED (N4), 0 DIFF. Java notification
does not run locally; it was started for the comparison with a self-contained configuration
(no config server, no Lighthouse, a scratch queue) and stopped afterwards.

## What Java notification is

A servlet service on commons2 (`commons2-security`, `commons2-jooq`, `commons2-mq`), not the
reactive commons. So:

- Spring Security's servlet header set: `X-Frame-Options: SAMEORIGIN`,
  `Content-Security-Policy: frame-ancestors 'self'`, no `Referrer-Policy`
  (`platform::http::HeaderStyle::Files`).
- A caller who is not signed in (or whose token security turns down) gets a **403** (empty in
  Java; coded in Rust, N14). There is no 401 and no `WWW-Authenticate` at all on this service
  (aca9929dd's rule is for the reactive commons; the servlet chain never sent a challenge here).
- `ControllerAdvice` (commons2) turns every exception into its answer, including Spring MVC's own:
  a missing or unreadable parameter, an unreadable body, an unsupported method and an unmapped
  path are all the catch-all **500** (`Please try again. A server error - <id> `). Rust answered
  the same until the error messages work (2026-10-17); they are now the 4xx that names the
  problem (N14), as files-manage did (crates/files/DIFFERENCES.md).

`NotificationController` has five mappings, not eight: `GET /notifications`, `GET /subscribe`,
`GET /new`, `GET /preference`, `POST /preference` (all under `/api/notification`). Spring adds HEAD
to the GETs and answers OPTIONS itself; the actuator endpoints are replaced by the platform's
(N10).

## Same on purpose (reproduced, quirks included)

- **Routes and binding**: `appCode` from the parameter, else the `appCode` header
  (`StringUtil.safeValueOf`); a repeated parameter joined with `,`; a blank `appCode` answers 0 or
  an empty page; `userId` converted as Spring converts a `BigInteger` (trimmed, `0x`/`#` hex, blank
  is absent, anything else a 400, N14); `Pageable` as `PageableHandlerMethodArgumentResolver`
  (page 0, size 20, at most 2000, unreadable numbers 0, `sort` echoed); `produces =
  text/event-stream` (a request that accepts only JSON finds no handler: a 406, N14); OPTIONS answers
  `Allow` and an empty `Accept-Patch`; HEAD answers the GET's headers.
- **CORS**: the servlet `CorsFilter` with any origin, header and method and no max age; preflights
  are answered before security, the `Vary` trio is on every answer, and cross-origin is decided as
  Tomcat sees the request (`http`, the `Host` header's name and port).
- **In-app list**: newest first (`ORDER BY CREATED_AT DESC`), the rows returned are then marked read
  while the page shows them as they were read; `type` is never in an item (jOOQ maps
  `NOTIFICATION_TYPE` to a `notificationType` property the class does not have); `createdAt` and
  `readAt` are epoch seconds; `PageableExecutionUtils.getPage(..., () -> -1)` totals, so a full
  page or an empty page past the first can say `totalElements: -1`.
- **Unread count**: unread rows of the caller in the app, optionally of one `type` (the stored
  `NotificationType` name, e.g. `ALERT`).
- **SSE**: the stream is filed under `"<userId>-<appCode>"`; it opens with
  `event:init / data:connected / id:<uuid> / retry:5000`; each notification is
  `event:notification` with `NotificationEventRecord` as pretty JSON split into `data:` lines,
  a fresh `id:` and `retry:5000`; a `:keepalive` comment goes to every stream every 15 s from one
  timer (not per stream); response headers `text/event-stream;charset=UTF-8`,
  `Cache-Control: no-cache`, `Connection: keep-alive`, `X-Accel-Buffering: no`. The frames are
  byte-identical to the ones Java sent on 2026-10-16.
- **Queue listener**: `notifications.mq.queues` (default `notifications1,notifications2,notifications3`),
  one consumer per queue working one message at a time; every message is acked once its run
  ends, whatever happened (the listener catches and logs every exception); only a body the JSON
  converter cannot read (not JSON, not an object, a field Jackson cannot bind, a content type
  without `json`) is rejected without requeue. The message is read as Jackson reads it into
  `NotificationQueObject` (unknown properties ignored, scalars coerced, `xdebug` not `xDebug`).
  Nothing declares the real exchange or queues (they already exist).
- **Sending** (`NotificationSendService`): the connection then the notification from core, with
  `x-draft: true` only for a draft message and on those two calls only (`NotificationDraftHeaderTest`
  ported); a missing definition ends the run quietly; email when the connection names a MAIL
  connection and there is an `email` template, in-app when the connection allows it and there is an
  `inapp` template; recipients from security's `users/internal/notification` with Java's
  `UsersListRequest` per target type (`User Id`, `Client Id`, `Client Code`; anything else asks
  for the whole app); email to every recipient first, then in-app; a failure anywhere stops the
  rest (an email error means no in-app).
- **Preferences are never read when sending.** `getInternalNotificationPreferecene` exists in Java
  but nothing calls it; the Rust port has no such read either.
- **Templates** (`AbstractTemplateService`): the notification's own language rule (the default
  language, or the rendered `languageExpression`, falling back to the default when blank), the
  `en` set for a blank language and the first set in core's order when the language has none;
  parts rendered with the FreeMarker subset shared with core (`connections::template`). A template
  without parts fails with `Internal Server Error (Unknown)`: Java throws `mail_send_error`, which
  its bundle does not have, so `getMessage` falls back to `unknown_error`.
- **In-app rows**: one per recipient (`NOTIFICATION_CATEGORY` `Default` when none), `title`,
  `description`, `image` and `url` parts into `TITLE`, `MESSAGE`, `MIME_URL`, `URL`; a missing
  title or description fails the insert (NOT NULL), and nothing is pushed.
- **SMTP** (notification's `SMTPService`, not core's): `false` without sending for a recipient
  whose address is null, blank, `NONE` or has no `@`, and for missing connection details,
  `mailProps`, user name, password or `fromAddress`; a refusal or an unreachable server is logged
  and the answer is still `true`.
- **SendGrid** (notification's `SendGridService`): no address check (a recipient without one, or a
  template without subject or body, fails the whole notification, as `Map.of` refuses nulls);
  a 4xx/5xx fails the notification; SendGrid's usual empty 202 answers `false` (no second send:
  that bug is core's, not this service's).
- **Preferences**: the caller's own, or another user's after `getClientByCode` (the caller's
  client), `getUserInternal` and `isUserClientManageClient(urlAppCode, userId, user's clientId,
  caller's clientId)` in that order, `User don't have access to this user Id : <id>` (403) when
  refused; security's own errors relayed with their status and message (`handleFeignException`,
  JSON answers only), a null user, client or answer the catch-all 500. A write evicts
  `cmn-notificationPreference:<appCode><userId>` everywhere (nothing reads it). Creating with no
  body stores a row without a preference and answers an empty 200; an empty map or no body on an
  existing row deletes it and answers `{ }`; two rows for one user and app fail the read (jOOQ
  `fetchOne`). The stored map is read back in MySQL's key order; a write answers the map as sent.

## Different on purpose

- **N1. In-app streams with several instances (same as Java, documented).** The open streams live
  in the process, in both implementations. A notification is consumed by one instance (one of the
  three queues, one consumer each), and that instance pushes it only to streams open on itself;
  a user whose stream is on another instance sees it only on the next list or count read. Two
  Java instances behave the same way today. Proposed fix (not built): after storing the rows, the
  consuming instance publishes `{key, frame}` on a Redis channel (e.g. `notificationInApp`), every
  instance subscribes and delivers to its own streams, and the local delivery is dropped in favour
  of the published one. The Redis connection already exists for cache evictions; message loss
  while an instance is disconnected only delays the event to the next read, which is no worse
  than today.
- **N2. Error bodies**: `stackTrace` is empty, the body is coded (N14), and the JSON is
  compact (all Rust units). Java sends its server stack and the exception's own text to any
  caller.
- **N3. Timestamps in UTC**: `READ_AT` and the preference `CREATED_AT`/`UPDATED_AT` are written as
  the current instant. Java writes the JVM's wall clock (`LocalDateTime.now()`), which is the same
  in production (UTC JVMs) but 5 h 30 m ahead locally (observed: a Java `readAt` read back as
  epoch + 19800). `createdAt` is MySQL's own and agrees in both.
- **N4. Key orders Java takes from reflection**: Jackson writes `PageImpl`'s properties, and Spring
  builds `Allow`, in an order that differs between JVM runs (two runs of the same jar on
  2026-10-16 wrote different orders). Rust writes one fixed order; the parity script compares
  pages as JSON and `Allow` as a set, and lists each page as EXPECTED.
- **N5. Unqualified tables**: Java's generated jOOQ names the `notification` schema in every
  statement, so a Java instance always writes the real `notification` tables whatever its
  datasource says. Rust uses the configured database (tests and parity run on `RUSTTEST_*`
  schemas).
- **N6. A stream that stops reading** is dropped after 256 queued events (`[sse] buffer`); Java's
  `SseEmitter.send` blocks the sending thread, which is the queue consumer, on it.
- **N7. Prefetch**: 10 deliveries buffered per queue (`[notifications] prefetch`); Java's is
  unbounded (`prefetchCount(0)`). Each queue is still worked one message at a time.
- **N8. A panic during a run** is acked and logged, like any other failure; a Java `Error` thrown by
  the listener would be requeued (and redelivered for ever).
- **N9. SMTP edge cases**: a template without a body fails before connecting (Java opens the SMTP
  transaction and fails while writing DATA; no mail either way, and the notification stops); a
  template without a subject sends an empty `Subject:` (Java leaves the header out).
- **N10. Health and metrics**: `/healthz`, `/readyz` (MySQL, and the queue consumer when `[mq]` is
  on) and `/metrics` replace `/actuator/**`. A gateway pool pointing at Rust notification needs
  `health_path = "/readyz"`.
- **N11. Where core is**: `[core] upstream` (the notification read) and the optional
  `connections_upstream` (the connection read): among the Rust units core-editor serves one and
  core-exec the other. Java's Feign `core` client reaches Java core, which serves both.
- **N12. The caller's context** comes from security (security-auth when `auth_upstream` is set) on
  every request, as everywhere in the Rust units; commons2 looks in the Redis `cmn-tokenCache`
  first. The answers are the same.
- **N13. Preference numbers** beyond 64-bit integers lose precision (read as doubles); Java keeps a
  `BigInteger`. MySQL's JSON type stores such numbers as doubles anyway.
- **N14. Coded error bodies and named bad input** (2026-10-17, ERROR_MESSAGES.md). Every error
  carries a stable `code`, a `message` in plain words in the request's language, an `action`
  when there is a next step, `params` and `locale`; Java's text goes to `debugMessage`. Codes are
  `NOTIF.*` (`messages/en.toml`) and the platform's `COMMON.*`.

  | Case | Java | Rust |
  |---|---|---|
  | not signed in | empty 403 | 403 `COMMON.SIGN_IN_REQUIRED`, or `COMMON.SIGNED_OUT` when a token or password was sent and refused |
  | another user's preference, not managed | 403 "User don't have access to this user Id : <id>" | 403 `NOTIF.USER_PREFERENCE_FORBIDDEN` (Java's text in `debugMessage`) |
  | missing `appCode`, unconvertible `userId` | 500 catch-all | **400** `COMMON.PARAM_MISSING`, `COMMON.PARAM_INVALID` naming the parameter |
  | body not declared as JSON, not JSON, not an object, over 16 MB | 500 catch-all | **415** `COMMON.BODY_NOT_JSON`, **400** `COMMON.BODY_UNREADABLE`, `COMMON.BODY_INVALID`, **413** `COMMON.PAYLOAD_TOO_LARGE` |
  | unsupported method, unmapped path (OPTIONS too) | 500 catch-all | **405** `COMMON.METHOD_NOT_ALLOWED`, **404** `COMMON.NOT_FOUND` |
  | `subscribe` accepting no event stream | 500 catch-all | **406** `NOTIF.STREAM_NOT_ACCEPTABLE` |
  | anything unexpected (MySQL, a null from security, security unreachable) | 500 "Please try again. A server error - <id> " | 500 `COMMON.INTERNAL_ERROR` |
  | security's own error | relayed: status and `message` | a coded body (a Rust unit's) passed on as it came; a Java body's `message` relayed as before |

  The 4xx statuses follow the approved plan (bad input is the caller's to fix, never a 500 that
  looks like our fault). `tools/parity_notification.py` compares the bodies by code
  (`tools/error_parity.py`) and lists these cases as EXPECTED. Not yet run against Java with
  these changes: Java notification was not running on the local stack when they were made.

## Found along the way (Java, worth knowing)

- Java notification is not running locally, and `notifications1..3` hold ~607 messages nobody has
  consumed. The local Rust configuration consumes scratch queues for that reason.
- Locally, Java notification's Feign call to Java core's
  `/api/core/connections/internal/notification/{name}` hung until its 60 s read timeout, twice,
  while curl got the same answer from Java core in 5 ms (JDK 26 `HttpURLConnection` client; Feign
  to Java security worked). The Rust client reads it fine.
- Spring Cloud Config's remote properties outrank command-line arguments for this service, so a
  `--spring.datasource.url` override does not apply (with N5, there is no way to point a running
  Java notification at a scratch schema).
- `isUserClientManageClient` is called with the named user as the managing side and the caller's
  client as the target: it asks whether the named user's client manages the caller's, which looks
  inverted. Kept; an owner call.
- The local `leadzump` and `leadzumptwo` notification MAIL connections have no `fromAddress`, so the
  notification service's SMTP sender skips every mail for them (answers `false`). If production's
  connections look the same, those apps' notification emails never go out.
