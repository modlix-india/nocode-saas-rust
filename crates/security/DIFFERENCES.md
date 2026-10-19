# security: differences from the Java security service

security-auth serves `AuthenticationController` (sign-in, tokens, the caller's context) and
security-internal the service-to-service routes (SPLIT.md), beside the Java security service, on
the same `security` schema, Redis and `evictionChannel`. What they do differently on purpose, and
the Java behaviours they keep although they look wrong. The first sections are security-auth's;
security-internal has its own sections at the end, and shares everything that applies to both
(error bodies, cache levels, the caller's context).

## Error bodies: coded, plain-language messages (all three units, 2026-10-17)

Every error the security units answer carries a stable code and a message written for the person
reading it, from the catalogue in `messages/en.toml` (codes `SEC.*`) and the platform's
(`COMMON.*`, `crates/platform/messages/en.toml`). The status codes are Java's, unchanged.

| | Java | security units |
|---|---|---|
| `message` | the bundle text (`Permission/Role User READ is required to use this operation`) | the catalogue text in the request's language (`You can't do this: your account does not have the View users permission.`) |
| `debugMessage` | the same text (or the cause) | Java's text under its key, `[forbidden_permission] Permission/Role User READ is required to use this operation`, or the cause, as before, for Spring's 400s and the 500s |
| added fields | none | `code`, `action` (when there is a next step), `params` (the values in the message, as words), `locale` |
| not signed in on a protected path | empty 401 | 401 with `COMMON.SIGNED_OUT` ("You're signed out. Please sign in again.") when a token or password was sent, `COMMON.SIGN_IN_REQUIRED` ("Please sign in to continue.") when none was |
| `@PreAuthorize` refusal | 403 `text/plain` "Access Denied" | 403 JSON `COMMON.PERMISSION_REQUIRED`, naming the permission in plain words and who can grant it; an anonymous caller gets `COMMON.SIGN_IN_REQUIRED` instead and learns nothing about permissions |
| Spring's 400s (missing or unconvertible parameter, unreadable body) | "Please try again. A server error - <id>" | `COMMON.PARAM_MISSING`, `PARAM_INVALID`, `BODY_MISSING`, `BODY_UNREADABLE`, `FIELD_MISSING`, `FIELD_INVALID`, naming the field when it is known; still 400 |
| 500s | "Please try again. A server error - <id>" | `COMMON.INTERNAL_ERROR`: "Something went wrong on our side. Error id <id>: give it to support." |

- Java callers and the pages read `message` as before; it is now the plain text. Rust units that
  relay a security refusal pass its code, params, message and action on as they came
  (`platform::security::refusal_error`, error messages phase 2), and their parity scripts compare
  those by code.
- Java values printed as `null` are left out of the message (`We couldn't find the client
  address.`); the Java text in `debugMessage` keeps them.
- No leaks: the 404-vs-403 behaviour is Java's, and a "not found" says only that the object was
  not found for the caller.
- The parity scripts compare errors by status and code (`tools/error_parity.py`): the code must
  stand for Java's text (its bundle key's template, or its Java text), and Rust's answer, put back
  into Java's shape, must then match everything else (status, headers, `debugMessage`, the body).
  Such cases are EXPECTED ("new error text, compared by code"); a code that does not stand for
  Java's text is a DIFF.
- The review sheet is generated from the catalogues: `tools/error_catalogue.py` writes
  `ERROR_CATALOGUE.md` (one row per code, Java's text beside the new one).

## Deliberate differences

| Where | Java | security-auth | Why |
|---|---|---|---|
| Error bodies | `stackTrace` holds the server stack | always `""` | Platform-wide: no stack to anonymous callers. The coded body is described above. |
| `internal/tokens/cleanup` | deletes tokens whose `EXPIRES_AT` (a UTC wall time) is before `LocalDateTime.now()` (the JVM's zone) | compares with UTC now | On a JVM east of UTC (the local stack runs at +05:30) Java deletes live tokens up to 5h30 before they expire; running the job once on 2026-10-15 removed 1,166 rows, current sessions included. Identical when the JVM runs in UTC. `LAST_USED_AT` (written in local time) is still compared in local time. |
| `authenticate` falling back to `authenticateUserForHavingApp` | when the sign-in into the user's profile app also comes up empty, it falls back again to the same app, without end (the request never answers) | the second miss answers 403 `User credentials mismatch` | A request that cannot finish is not behaviour worth keeping. |
| `userRoles` authorities | when the user has app-less roles and none for the app, `getUserAuthorities` appends the profile authorities to the cached list itself, so the cached list grows on every request until evicted | the cached list is copied | Unbounded growth of a cached list. Unreachable on the local data (no `security_v2_user_role` rows). |
| `stringAuthorities` order | as computed when the list was cached, possibly long ago, in Redis (`cmn-profileAuthsById_<id>`) | computed with Java's algorithm on current data | Rust has no Redis level. Same authorities either way; after an eviction both give the same order (checked on the local stack). |
| `client.managagingClient` in sign-in/verify/refresh responses | present when `/users/findUserClients` ran on that JVM earlier: it sets the field on the cached `Client` | never present | Java leaks a mutation of its cache into later responses. |
| Cache levels | Caffeine L1 + Redis L2 (Java-serialized) | in-process L1 only, same names, joins `evictionChannel` both ways | Rust cannot read Java-serialized values. A Rust copy lives at most 60 minutes (Java's L1 TTL); Java's L2 lives until evicted. |
| `user.timeZone` | `ZoneId.of` on the JVM's tzdb | chrono-tz | Same results for the zones in use (`Asia/Kolkata`, `Asia/Calcutta`, offsets); a rare id one database knows and the other does not would sanitize differently. |
| JWT parsing | jjwt also inflates `zip` (compressed) tokens | refused | Nothing issues compressed tokens. |
| `HashMap` order of roles | exact, including tree bins | modelled except for 8+ ids in one hash bucket | Ids that collide 8 times in one bucket do not occur. |
| Request bodies | 50 MB limit (`getInMemorySize`) | 1 MB, 413 above | Sign-in bodies are a few hundred bytes. |

## Java behaviour kept as it is

Kept so both implementations answer alike while both run; each is a candidate fix in Java first.

- An app's platform subdomain host (`<appcode>.local.modlix.com`) with no `clientCode` header makes
  the anonymous context a 500 ("Empty input string"): the subdomain pattern has an empty
  identifier. The gateway always sends `clientCode`, so callers through it never see it.
- `refreshToken` mints the new token without an `appCode` claim; the next context takes the app
  from the request header.
- `authenticateWithOneTimeToken` answers a context with `"authenticated": false`
  (`makeContextAuthentication` never sets it).
- `refreshToken` re-sets the `Authorization` cookie only when the cookie sent is blank (with the
  blank value).
- The failed-attempt check compares the counter read at the start of the sign-in: the lock lands
  on the attempt after the one that reached the limit, and a user whose expired lock is lifted
  during the sign-in is locked again by the next wrong attempt.
- A policy row with `NO_FAILED_ATTEMPTS` null: the attempt is counted, then the answer is a 500.
- `PASSWORD_EXPIRED` and lock messages print `null` for a missing reason.
- A profile whose role is also named by a client's override profile: Java sorts and repeats the
  roles it has kept instead of choosing among the candidates, so the role is dropped and the
  last kept one repeated; when nothing is kept yet it is a 500 (`NoSuchElementException`).
- `getProfileIds` runs on every signed-in request (uncached), as in Java.
- Resend with `resendSameOtp` sends the stored BCrypt hash, not the code.
- Locks (`LOCKED_UNTIL`), `LAST_USED_AT`, OTP expiry and the anonymous user's timestamps use the
  process's local wall time, as the JVM's `LocalDateTime.now()` does; token expiry uses UTC.
- Social sign-in messages `social_login_failed` and `session_expired` are missing from the Java
  bundle and read "Internal Server Error (Unknown)".

## Not differences, but worth knowing

- 401 on protected paths carries no `WWW-Authenticate`, per `ISecurityConfiguration` since
  nocode-saas aca9929dd (2026-10-15), in both. Java's body is empty; ours is the coded body above
  (the parity script's six 401 cases are EXPECTED by code).
- OTP delivery on the local stack: `config/security-auth.toml` sets `otp.publish_events = false`
  and no SMS key is configured, so the `USER_OTP_GENERATE` event and the SMS are logged instead
  of sent (as Java's `TwoFactorService` does without a key). With `MODLIX__MQ__URI` and
  `publish_events = true` it publishes the same message to the same exchange and keys as Java.
- Once `AuthenticationController` traffic goes to security-auth, nothing writes the Redis
  `cmn-tokenCache` for those tokens, so the other Java services' `FeignAuthenticationService`
  (which reads that cache first) asks security for every request instead of every new token.
  Measured locally: signed-in context p50 0.76 ms in Rust against 2.66 ms in Java.
- The Java services reach `internal/securityContextAuthentication` through Feign on
  `eureka:SECURITY`, not through the gateway. Routing the controller's paths at gateway-rust
  moves browser traffic only; the service-to-service share moves when security-auth is given an
  Eureka name of its own (`[eureka] register_as`) and commons-security's Feign client points at
  it.

## security-internal: deliberate differences

| Where | Java | security-internal | Why |
|---|---|---|---|
| Fills on cached objects (`?fetchOwners`, `fetchManagingClient`, `fetchClients`, ...) | `fillDetails` sets the parts on the cached `Client` / `User` itself, so later plain reads on that JVM (and nested users or clients in other answers) carry `owners`, counts, `client`, `managingClient`... | the parts are added to the one answer; cached rows are never changed | The same leak as `client.managagingClient` above. The parity script strips these properties where they were not asked for and reports the case as EXPECTED. |
| `GET internal/billing/serving-status` | always 400 "Type mismatch." | answers the status | `InternalBillingController` has no `@InitBinder` for `ULong` (the JOOQ controllers do), so Java can never convert `clientId`. Nothing calls the route yet. It creates the caller's wallet when the app is billed, as `getServingStatus` intends. |
| `?fetchProfiles=true` on the user routes | `ProfileService.fillUser`: each assigned profile read (with its arrangement merge) through a concurrent `flatMap` | the same reads, in the order the user's profile rows come back | Java's order is completion order. The parity script compares the `profiles` lists by id and reports a different order as EXPECTED. |
| `fetchCreatedByUser` / `fetchManagingClient` on a list of clients | a concurrent `flatMap`: the list comes back in completion order | the list's own order (or Java's `HashMap` order when another fill reordered it) | Java's order is not deterministic. |
| `filterManagedClientCodes` | `flatMap(..., 16)`: completion order | the request's order | The same. |
| Wallet event `data.balance` | the `BigDecimal` as Jackson writes it (`390.0000`) | the same value as a JSON number (`390.0`) | The event body goes through `crates/connections`' JSON writer, which has no exact decimals. Consumers read a number either way. |
| `getAppUrl` when the stored URL property value is null | `Mono.just(null)`: 500 | the same 500 | (Listed because it is easy to "fix" by accident.) |
| `getLastUpdated` with certificates but no client URL at all | `NullPointerException` (500) | the certificate's time | Unreachable: a certificate always belongs to a URL. |
| `isUserClientManageClient` / `doesClientManageClient` without their ids | `NullPointerException` (500) | the same 500, Java's message | Kept. |

## security-internal: Java behaviour kept as it is

- An anonymous caller on a tenant's host (or a signed-in non-SYSTEM user) gets the DAO
  restrictions: `clients/internal/query`, `clients/internal`, `users/internal`, `users/internal/query`
  and the batch reads see only what that client (or the caller's reporting tree) manages; an
  anonymous tenant caller sees no clients at all. The services call these routes without a host,
  so they are SYSTEM's anonymous caller and see everything.
- `users/internal/clients/batch` turns every query parameter into a filter
  (`ConditionUtil.parameterMapToMap`): `appCode=x` both fills and restricts the users to app `x`.
- A list parameter (`clientIds`, `userIds`, `profileIds`) must be repeated; one value with a comma
  is a 400 "Type mismatch." (the `ULong` binder converts the whole text).
- The `appId` / `appCode` filter shortcuts of `UserDAO` and `ClientDAO` negate inside and the base
  filter negates again, so `"negate": true` on them is a double negation.
- `trimBackSlash` counts from the end of the untrimmed URL: a leading space keeps one trailing
  slash, a trailing space is a 500.
- `appDependencies`, `appBillingConfigByCodes` cache an absent answer too (`cacheEmptyValueOrGet`):
  a dependency or config added later is seen after an eviction.
- `meter/security` and `reconcile` run with the server's local date and time, as the JVM's
  `LocalDate.now()` does; AI charges are dated the same way.
- `getUserAdminEmails` / `getOwnersEmails` answer `Map.of(...)`, whose key order changes per JVM
  start; Rust writes `emails` first.

## security-internal: not differences, but worth knowing

- The billing writes (`charge`, `charge-ai`, `meter/security`, `reconcile`) are Java's statements
  in Java's order, without a transaction, as in Java; the transaction row's unique idempotency key
  is what makes a repeat harmless. The parity script does not call the ones that would charge a
  real wallet; the statements are tested inside a rolled-back transaction instead.
- The wallet events go through `crates/connections`' publisher. `config/security-internal.toml`
  sets `[wallet] publish_events = false`, so locally they are logged, never published.
- `internal/cache` (`DELETE`) evicts every `cmn-*` cache in Redis, for every service on the stack,
  exactly as Java's does; any signed-in caller may, as in Java.

## security-admin piece 3 (billing): deliberate differences

| Where | Java | security-admin | Why |
|---|---|---|---|
| `GET invoices/{id}`, `GET invoices/{id}/documents` | always 400 "Type mismatch." | answered | `InvoiceController` has no `@InitBinder` for `ULong` (the JOOQ controllers do), so Java cannot convert any id; the same gap as `internal/billing/serving-status`. Both are reads, served with `readById` / `readDocumentKeys`' checks and `@PreAuthorize`. Nothing calls them today (the sitezump invoice page's call to `documents` is in an `onLoad` that never runs). |
| A write a database constraint refuses (a second config for the same client and app, ...) | 500, `debugMessage` jOOQ's `SQL [insert into ...]; <MySQL message>` | 500, `debugMessage` sqlx's `error returned from database: 1062 (23000): <MySQL message>` | The status and `message` are the same; Rust does not render jOOQ's SQL text. |
| A `BigDecimal` in a request body (`tokens`, `price`, ...) | read from the JSON text: `1.50` keeps scale 2 | read through a double: `1.50` is `1.5` | `serde_json` here has no exact numbers. The value is the same; only a scale echoed back (a quote's `tokens`, a CUSTOM bundle's `baseAmount`) can print shorter. Values read from the tables keep the column's scale. `PATCH` bodies go through a double in Java too. |
| `billing/razorpay/webhook` body | Gson's lenient reader (single quotes, unquoted names and comments parse; a duplicate key fails) | strict JSON | Razorpay sends strict JSON; a body only Gson accepts is a no-op here. |
| Invoice event `data` numbers | the `BigDecimal` as Jackson writes it (`1178.8200`) | the same value as a JSON number (`1178.82`) | The event body goes through `crates/connections`' writer, as the wallet events do. |

## security-admin piece 3 (billing): Java behaviour kept as it is

- `POST wallets/{walletId}/adjust` answers as Java does: the bare 401 for an anonymous caller,
  then "Type mismatch." for every id (`WalletController` has no `ULong` binder, so Java never
  reaches `adjust`). `[billing] serve_wallet_adjust = true` serves the ported `adjust` instead
  (the path, `tokens` and `reason` as Spring reads them, `ROLE_Owner`, then the service's checks);
  it changes balances, so it stays off until the owner turns it on.

- `PATCH billing-bundles/{id}` and `PATCH billing-configs/{id}` skip `@PreAuthorize`:
  `update(id, fields)` calls `update(entity)` on the service itself, past Spring's proxy. The
  config's management checks still apply. A key without a setter of the DTO's own class (`id`,
  `createdAt`, unknown names) is ignored; a value the setter's type cannot take is a 400
  "`<field>` field cannot be updated, it might not be available or unmodifiable".
- `PUT` and `PATCH` copy the editable fields only (`updatableEntity`), and jOOQ's null rules
  apply: a nullable column missing from the body is cleared, a NOT NULL one keeps its value.
  `createdBy` stays null on create and `updatedBy` is never set (`getLoggedInUserId` is empty).
  A config whose `PAYMENT_GATEWAY_CONFIG` is NULL reads as an empty map and a later update writes
  `{}` back.
- The generic lists (`GET billing-bundles`, `GET billing-configs`, their `/query`) are refused
  with 403 after the query or body is read (a bad body is still the 400).
- `GET billing-configs/{id}` of a config the caller may not see is a bare 404; of a missing one,
  the DAO's 404 JSON. `PATCH`/`PUT` of an invisible one answer 200 with no body.
- A missing `appCode` (or, where read, `clientCode`) header is a 500 "Cannot invoke
  "Object.toString()" because "args[0]" is null" (the cache key); an unknown app answers the
  empty `Mono` (200 no body), 204 for `wallets`, `{ }` for `billing-profile` and `wallets/plan`,
  ACTIVE for `wallets/status`, an empty page for `wallets/transactions`.
- `wallets/transactions` is not sorted unless `sort` is given (the Javadoc says newest first).
- A purchase creates the PENDING invoice (and takes the next number) before the gateway is
  called: a seller without keys, or a Razorpay error, leaves that invoice behind with a 500.
- The webhook reads the payment, the invoice and the seller's config before it checks the
  signature: a known payment whose invoice is gone is a 404; a failure after the wallet credit
  (the invoice event) is a 500 with the credit kept. Unknown, unverified or non-terminal events
  answer "OK".
- The serving bundles, the display status and the plan resolve the config up the client's
  hierarchy over every non-DELETED config, INACTIVE included.
- `repay`'s refusal reads "Required params {invoice (already PAID)} for $ not found" (the
  bundle's `params_not_found` with one parameter).

## security-admin piece 3 (billing): not differences, but worth knowing

- `[billing] razorpay_base_url` is where a purchase's Razorpay calls go (Razorpay's API by
  default); `config/security-admin.toml` points it at a closed local port, so a local purchase
  that gets that far answers 500 instead of reaching Razorpay.
- Razorpay, files' `internal/secured/createKey` and the e-mail's app URL go through
  `admin::billing::service::Outside`; the tests answer them in process and the parity script
  never drives a request that far (a purchase is only sent with an unknown bundle or for a client
  the caller does not manage, a repay only for PAID, unknown or other clients' invoices, a webhook
  only for unknown payments or with a wrong signature). Locally `[files] upstream` points at
  files-manage.
- The billing writes are Java's statements in Java's order without a transaction, as in Java;
  the ledger row's unique idempotency key keeps a replayed credit from counting twice.
- The billing tables have their own reader and writer (`data/billing_admin.rs`) rather than
  `data/crud.rs`: the statements run on one connection so the live tests can run them inside a
  transaction they roll back. The null rules are the same.
- Writes to a config evict `appBillingConfigByCodes` (and credits `walletStatus`) everywhere, as
  Java does.

## security-admin piece 2 (clients, apps and hosting): deliberate differences

| Where | Java | security-admin | Why |
|---|---|---|---|
| `POST clients` | `@PreAuthorize("hasAuthority('Authorities.Client_CREATE')")` on `ClientService.create` is never applied (observed: a `Logged_IN`-only user's request reached the insert); every other `@PreAuthorize` of this piece is | 403 `Access Denied` without `Client_CREATE` | A missing authority check on tenant creation is a hole, not behaviour: a signed-in user with no authority could create a client under their own and become its manager. Probably the bridge method of the two-level generic override (`ClientService.create(Client)` over `AbstractSecurityUpdatableDataService.create(D)`); worth checking the other `AbstractSecurityUpdatableDataService` subclasses that override `create`. |
| The SSL routes that reach the certificate authority (`POST ssl` after its checks, `GET ssl/certificate`, `GET ssl/request/challenge`, `POST ssl/request/challenges`, `POST ssl/internal/renew-certificates`) | acme4j against Let's Encrypt (the local stack has credentials), BouncyCastle for the key pair and CSR | 500 `lets_encrypt_credentials`, answered before anything is written or deleted (Java without credentials deletes a request's challenges, or leaves a request row behind, before failing); a renewal sweep reports each expiring certificate as failed with that message | This unit has no ACME client and no RSA (it must never contact a real authority, and the crate has no RSA or X.509 dependency). The whole flow is behind the `Acme` and `CertCrypto` traits (`admin/clients/ssl.rs`) and tested end to end with in-process fakes; a real client plugs in there. |
| `POST ssl/external` | `CertificateFactory` and an RSA encrypt/decrypt round trip; `debugMessage` is the JCA exception's text | the certificate's expiry and the key's RSA modulus and exponent compared through a small DER reader (`x509.rs`); the same `message` for each problem, `debugMessage` Java's only for a body with no PEM block ("Could not parse certificate: java.io.IOException: Empty input"), else the message | Matching modulus and exponent is exactly when Java's round trip succeeds; the JCA's wording for other parse failures is not reproduced. |
| Client policies (`clientPasswordPolicy`, `clientPinPolicy`, `clientOtpPolicy`) and app integrations | read through `cacheEmptyValueOrGet` (`clientPinPolicy` ... by `clientId:appId`; `integrationPlatform` by `String.join(clientId, ":", appId, ":", platform)`) | read from the database each time; writes still evict Java's entries with Java's keys | Rust has no Redis level and these reads are not hot; reading the row is never stale. |
| A write a constraint refuses (a duplicate URL pattern or app code, a client without a code, an app with access rows hard-deleted) | 500, `debugMessage` jOOQ's `SQL [...]; <MySQL message>` | 500, `debugMessage` sqlx's | As in piece 3. |
| `POST applications/reg/{appCode}/{urlPart}` with a value that does not convert | `ObjectMapper.convertValue`'s `IllegalArgumentException`: 500 with Jackson's text | 500 "Cannot deserialize value" | Jackson's message is not reproduced. |
| `createAndApply` / `makeTransport` | `TransportService` returns `Mono.empty()` | the same empty 200 | (Listed because the Java service is a stub.) |
| `clienturls/draft/token` expiry | `security.draftToken.expiryMinutes` (30 by default) | 30 minutes | The setting is not in this unit's configuration. |
| Cloudflare custom hostnames | configured by `security.cloudflare.apiToken` / `zoneId` (absent locally, on dev and on stage) | never configured | The settings are not in this unit's configuration; the client (`cloudflare.rs`) is written and tested against an in-process fake. |
| Lists Java fills with a concurrent `flatMap` (registration objects' fills, `filterManagedClientCodes`) | completion order | the list's order | Java's order is not deterministic. |
| A registration's other apps (`autoAddRegObjectsFromOtherApps`), the access it grants (`addClientAccessAfterRegistration`) | the apps concurrently (`flatMap`) | one after another, in the rows' order | The writes are the same; Java's interleaving is not deterministic. |
| A client's hierarchy row after `POST clients` | also `put` into Java's `clientHierarchy` cache | read on first use | Rust caches L1 only; the row is the same. |
| Users and clients a `clients` page nests (`owners`, `createdByUser`, `clientManagers`, `managagingClient`) | taken from the in-memory `userCache` / `clientCodeId` cache objects, which `UserService.readById(id, queryParams)` and `ClientService.readById(id, queryParams)` fill IN PLACE; so a nested user carries `profiles` (or `client`, `designation`, ...) and a nested managing client carries `owners` and user counts whenever an earlier request, anyone's, asked for them, until the entry is evicted | only what this request asked for: nested objects carry no fills, a nested client's counts are 0 | Java's output depends on which requests came before; the parity script compares these pages with the nested fills left out and reports them as this entry. |

## security-admin piece 2 (clients, apps and hosting): Java behaviour kept as it is

- `GET applications/clients/{appCode}` without `onlyWriteAccess` is a 500 (the `Boolean` is
  unboxed into the service's `boolean`).
- `GET applications/findAnyApps` for a SYSTEM caller, or one in the client they signed in from,
  is a 500: `Page.empty()` has no offset Jackson can write.
- `AppService.delete` and `deleteEverything` compare the app's client with the app's own id.
- `DELETE applications/{id}/access` on an app the caller may not change answers 403 with the
  unknown-key message: the literal "Application access" is passed as the message key.
- `PATCH applications/{id}/access` answers the matched row, so an unchanged flag is `true`.
- `PATCH clients/{id}` and `PATCH` of a policy run `update(entity)` inside `update(key, fields)`:
  two sox log rows and two client activities per patch. A null for a primitive (`tokenValidityMinutes`)
  is its default, 0.
- `PUT` of a client, app or policy writes every column of the DTO: what the body leaves out is
  stored as null (or the DTO's default: a policy's `length` 4, a client's `tokenValidityMinutes`
  0), except `NOT NULL` columns, which keep their value.
- The sox and activity rows these services write have no `CREATED_BY` (Java's detached
  `.subscribe()` carries no security context); apps and policies are created without a creator.
- `POST clienturls` for a client the caller does not manage answers an empty 200.
- `POST applications/reg/...` checks even a SYSTEM caller's right to the named client (the
  `Mono.just(true)` meant for SYSTEM is never returned), writes `CREATED_AT` as the server's local
  wall time, and fills a designation's `department` and a user designation's `designation` with
  the object's own type, so the setter never takes them (they stay unset).
- `POST applications/reg/{appCode}/{urlPart}/query` without `page` or `size` is a 500 (unboxing).
- `request_existing`, `unsupported_platform` and `session_expired` are missing from the bundle:
  "Internal Server Error (Unknown)".
- `GET ssl?urlId=x` and `DELETE ssl/x` are 500s (`ULong.valueOf` outside the binder);
  `POST ssl/query` without a condition is a 500; `GET ssl` without `urlId` is a 404 for
  "ClientUrl with id null".
- `GET clientXPolicy/codes/policy` without the `clientCode` or `appCode` header is a 500 ("t1",
  "t2": `Tuples.of` refuses a null).
- `GET clients/socialRegister/callback` with an unknown or missing state is a 500 "Invalid state".
- The social sign-up redirects build their query with `UriComponentsBuilder.build().toUri()`:
  only characters illegal in a URI are encoded, so `&` or `=` in a recorded parameter is not.

## security-admin piece 2 (clients, apps and hosting): registration

`POST clients/register`, `POST clients/register/otp/verify`, `POST clients/socialRegister`,
`GET clients/register/events` and `POST clients/appRegister` (`admin/clients/register.rs`), over
piece 1's user side of it (`admin/users/registration.rs`). Kept as Java has them:

- No transaction: a registration that fails after its client is made (a secret the policy cannot
  generate, a files service that refuses) leaves the client, as Java's does.
- The registering app is also the first of the apps it "additionally" registers on, so its file
  access paths are made twice and the user's registration objects (roles, profiles, departments,
  designations) added twice.
- An empty chain is an empty 200: an unknown app on `register` or `socialRegister`, an unknown
  URL client, an unknown parent client.
- `otp/verify` without any secret or pass type is Java's NPE (500); `register/events` without a
  pass type is one too, after the user is read. With `PASSWORD` it signs in with the stored hash
  (so it fails, and counts an attempt); with `OTP` it answers an empty 200. It reads the app URL
  with the client's code as the app code and the app code as the client code.
- `POST clients/appRegister` is open to any signed-in caller who names an owner's user id.
- `CREATED_BY` of the registered client, its app access and its URL is the caller's id: 0 for an
  anonymous sign-up. The client's `BUSINESS_TYPE` is the column default (the request's is not
  copied).
- A registration body that is not JSON is 415 (no `Content-Type` is `application/octet-stream`),
  except a `POST` with no type and no body, which is the missing body's 400, as WebFlux's argument
  resolver answers; the other routes of this piece read an untyped body as JSON.
- The files service's `internal/accesspath` goes to `Admin.files` (`[files] upstream`).

## security-admin piece 2 (clients, apps and hosting): not differences, but worth knowing

- The DTOs this piece writes whole are described once each as an `entity::Entity` (properties in
  Jackson's order, the column each maps to, write-only and primitive flags, the setters a `PATCH`
  may use); the SQL is `data/crud.rs`'s, with jOOQ's null rules.
- Every write evicts what Java evicts, everywhere: `clientCodeId` / `clientId` for clients;
  `appInheritance`, `uri`, `clientUrl`, `gatewayClientAppCodeType`, `byAppCode`, `byAppId`,
  `appStatus`, `appReadAccess` / `appWriteAccess`, `appDependencies` / `appDepList` for apps;
  `clientUrl`, `uri`, `gatewayClientAppCodeType`, `certificateCache`,
  `certificatesLastUpdatedCache` for client URLs.
- `APP_ACCESS_CHANGED` events go through `Admin.events` (`[events] publish_events = false`
  locally: logged).
- The provider calls of the social sign-up (Google's and Meta's token and profile endpoints) are
  `registration::HttpProviders`; the tests use an in-process fake, and the parity script never
  follows a redirect.
- The parity script's writes stay on scratch objects: two apps (`zzparityjava`, `zzparityrust`)
  created and deleted per run, and two clients (`ZZPJAV`, `ZZPRUS`) the API can only mark
  DELETED, so each run brings the same two back. Draft-edit grants minted on the scratch apps
  expire on their own.

## security-admin piece 1 (users, profiles, roles, organisation): deliberate differences

| Label | Where | Java | security-admin | Why |
|---|---|---|---|---|
| U1 | `POST users`, `POST rolev2` | `@PreAuthorize` on `UserService.create` (`User_CREATE`) and `RoleV2Service.create` (`Role_CREATE`) is never applied, like `ClientService.create` in piece 2 (observed: a `Logged_IN`-only member gets `forbidden_create` from the later checks, so in their own client the create goes through); every other annotation of this piece is applied | 403 `Access Denied` without the authority | The same hole as piece 2's: creating users or roles needs the authority the annotation names. The two-level generic override (`create(User)` over `AbstractSecurityUpdatableDataService.create(D)`) is the likely cause; `ProfileService.create`, `DesignationService.create` and `DepartmentService.create` do apply theirs. |
| U2 | `authorities/parse` for a malformed expression | kirun-java's parser: `Authorities.A +` reads as `(Authorities.A)`, `()` is "No expression found to evaluate", an extra operator is named by its enum (`BITWISE_AND`) | kirun-rust's (a port of kirun-js): `Authorities.A +` stays the whole text, `()` is an empty node, the operator is named by its symbol (`&`) | Only the `reason` text of an unsupported expression differs; every well-formed expression (the 30 the parity script sends) parses the same. Belongs to kirun-rust, not to this unit. |
| U3 | Lists Java fills with a concurrent `flatMap`: `app/{appId}/profiles`, `users?fetchProfiles`, `users/{id}/app/{appId}/assignedProfiles`, `client-managers/{uid}`, and the ties of `users/findUserClients` (sorted by client name only: two users of one client, or two clients of one name) | completion order | the order of the rows (for the picker's ties, Java's `HashMap` order of the user ids) | Java's order is not deterministic; the parity script compares these lists by id. |
| U4 | A profile whose overrides come from two or more clients (none locally) | `readRootProfile` merges each override with `DifferenceApplicator` on a bounded-elastic scheduler, so which merge lands last is a race | the overrides merged in the hierarchy's order, farthest client first | With one override (every override locally, and the one the parity script makes) both give the same profile, byte for byte. |
| U5 | Cached objects Java fills in place (`client.activeUsers` and the other counts, a picker's `managagingClient`, a user's `profiles`) | carried by later reads that did not ask for them | only what the request asked for | The same leak as piece 2's and security-internal's; the parity script strips these properties where they were not asked for. |
| U6 | `USER_INVITED`, `USER_<TYPE>_CHANGED`, `USER_<TYPE>_RESET_DONE`, `USER_OTP_GENERATE` | published on the `events` exchange | published through the unit's `EventSink` (`[events]` / `[otp] publish_events`, off locally: logged) | Locally nothing is published. The invite mail's `urlPrefix` is the newest LIVE client URL of the app (the invited client's, else any), which is what `getAppUrlInternal` answers for the URLs that exist locally. |
| U7 | `GET users/{id}` for a user of another client | `UserService.read` checks only `User_READ`: any holder reads any user by id, whatever the client | the user is answered to SYSTEM, to the user's own client, and to a caller who manages the user's client (`isUserClientManageClient`: the client is managed by the caller's client, and the caller holds a client-manager role or is assigned as that client's manager); anyone else gets the 404 a missing id gets | Decided 2026-10-17: cross-client reads are allowed only as the client's manager. The 404 does not reveal that the id exists elsewhere. The other user routes already checked management (update, delete, reporting manager, designation); only this read did not. |

## security-admin piece 1: Java behaviour kept as it is

- A request body's `password`, `pin` and their `*Hashed` flags are `@JsonIgnore`d on `User`: `POST users`
  never sets a password (the user is created without one; `updatePassword` sets it).
- `POST app/profiles` with an `id` and the caller's own client UPDATES that profile (an override is
  made with `rootProfileId` and no `id`); `PUT` is the same route.
- `DELETE app/profiles/{id}` resolves the profile through the caller's hierarchy first: as a client
  that overrides a root, the id of the root deletes the override; as SYSTEM, the id of an override
  resolves to the root (and is refused while overrides exist).
- `UserService.update(key, fields)` reads `userName` / `emailId` / `phoneNumber` with `toString()`: a
  JSON null for one of them is a 500 (`NullPointerException`).
- A PATCH that cannot convert a `ULong` field is a 500: the deserializer's message service is null in
  that mapper, so its exception is a `NullPointerException`; any other field that does not convert is
  the 400 "<field> field cannot be updated". A JSON array for a `ULong` field reads as null.
- A body's `ULong` accepts a number, digit text or an object's `id`, and reads an array as null; a
  decimal (`2.0`) is a 400.
- `PUT users/{id}` without `clientId` is a 500 (the client-type cache key cannot be made).
- `ProfileService.hasAccessToRoles(clientId, roleIds)` passes the user's client id as the app id, so
  assigning a role to a user (`users/{id}/assignRole/{roleId}`) only passes for roles reachable through
  the caller's profiles of an "app" with that id, or app-less roles of the caller's own client.
- `UserService.create` ignores the password policy result and the `checkUserExists` answer (only an
  individual client's refusal, or an unknown client, stops it).
- Designation and role `PATCH` log the update twice (sox and client activity), as `update(key, fields)`
  ends in `update(entity)`.
- A Department create or update whose parent is not allowed (another client's, or no department at
  all) is a 403 with the unknown-key text; a Designation's update is a 404.
- `client-managers/migrateTo/{uid}` answers the rows added plus the rows removed (with
  `removeManager`, moving one client answers 2).
- `restrictClient` that cannot act (client not managed, no app access) answers 200 with no body.
- `findUserClients` (anonymous) with no identifier lists every non-deleted user under the client.

## security-admin piece 1: not differences, but worth knowing

- Profile arrangements keep Java's map kinds: a map read from the JSON column keeps MySQL's key order
  (`LinkedHashMap`), a merged map is iterated in Java `HashMap` order, and `fillProfileArrangements`'
  `putIfAbsent` lands keys where each kind puts them (`admin/users/arrangement.rs`).
- Password and PIN policies are read from `security_client_password_policy` / `_pin_policy` up the
  client hierarchy on every check (Java caches them by `clientId:appId`); the history check compares
  against `security_past_passwords` / `_pins` as Java does.
- The registration helpers piece 2's client registration uses (`createForRegistration`,
  `addRegistrationObjects`, `makeOneTimeToken`, ...) live in `admin/users/registration.rs`.
- The parity script makes its scratch objects on both sides, in clients made for each run (and a
  client below each, which overrides one of the run's own profiles), and names no id the run did not
  create. It runs Java's event-publishing success paths only on Rust and never sends Java a profile
  override create (one hung Java security for about four minutes on 2026-10-16).
- `tests/live_admin_users.rs` (gated on `SECURITY_AUTH_LIVE=1`) runs the same flows in process against
  the local schema, in its own scratch clients `ZZRUL` and `ZZRUM` (brought back each run and swept of
  anything a failed run left).


## App create and delete evict everything cached against the app code (2026-10-19)

Java `AppService.create`, `delete` and `deleteEverything` evicted only `appInheritance`, `uri`,
`byAppCode`, `byAppId` (and a few URL caches on delete). They left `appReadAccess`,
`appWriteAccess`, `byAppCodeExplicit`, `appDependencies`, `appDepList` and `inheritanceOrder`, and
several of those cache negative or empty answers (a `false` access answer for an app that does not
exist yet, an empty inheritance order, an empty dependency list). An app deleted and created again
under the same code was then served its predecessor's answers: reads of the new app's documents
came back "X with id ... not found" (a refused access check is reported as not found), and reads
by name found nothing. Seen repeatedly in the AppBuilder eval runs, which delete and recreate their
apps every run. The Rust routes now also evict all of those (`apps::evict_app_code`): whole caches
for the ones keyed `app:client` / `app:url:client` and for the dependency caches, by code for the
rest. Evictions are published, so they reach every Rust process and any Java one still listening.
