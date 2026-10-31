# Splitting security into Rust units

The Java security service (`../nocode-saas/security`, 302 route mappings in the source) becomes three Rust units that
share one library (this crate) and run beside Java on the same `security` schema and the same
Redis, exactly as security-auth does today.

| Unit | Port | Routes | Who calls it |
|---|---|---|---|
| security-auth | 8101 | `AuthenticationController` (13) | browsers through gateway-rust; every Rust unit's caller context (`[security] auth_upstream`) |
| security-internal | 8112 | the service-to-service routes (55) | Rust units through `platform::security::SecurityClient`, later Java services |
| security-admin | 8113 | everything else (223) | browsers through gateway-rust |

None of the three registers in Lighthouse. Java services reach security through Feign
(`lighthouse:SECURITY`), and Feign picks any instance of that name, so a Rust unit registered under it
would have to answer every one of the 302 routes. Until Java security is retired, Java callers keep
going to Java; Rust callers are pointed at the Rust units by configuration.

## How a request picks its unit

- Browser traffic comes through gateway-rust, which needs path routing for `/api/security/**`:
  the auth paths to security-auth, the rest to security-admin (Java until it is ported). nginx
  already refuses public `/internal/**`, so the gateway never routes there.
- Rust units use `[security] upstream` (Java today) for everything, `[security] auth_upstream`
  for `AuthenticationController`'s paths and `[security] internal_upstream` for
  security-internal's (`platform::security::{is_auth_route, is_internal_route}`). One
  `Upstream` carries the three (`platform::security::security_upstream`, `Upstream::base_for`),
  for platform's `SecurityClient` and for the units that build their own security requests
  (core, notification, gateway-rust's host and draft resolution). Every local and production
  configuration sets both.

## What decides the unit of a route

- **auth**: the 13 `AuthenticationController` mappings, including its two `/internal/` ones
  (`internal/securityContextAuthentication`, `internal/makeOneTimeToken`,
  `internal/tokens/cleanup`): they share the token code, and they are already ported.
- **internal**: every other mapping with an `/internal` segment, plus `AbstractCacheController`'s
  `internal/cache` routes. Callers are services, not browsers. Most are open to anonymous
  callers in Java's `SecurityConfiguration` (`clients/internal/**`, `applications/internal/**`,
  `clienturls/internal/**`, `users/internal/**`, `app/profiles/internal/**`,
  `internal/billing/**`); `internal/cache/**` and `ssl/internal/certificates` need an
  authenticated caller.
- **admin**: the rest. One exception to the path rule: `POST ssl/internal/renew-certificates`
  is a worker trigger that renews certificates with ACME and writes them, so it lives with the
  rest of `SSLCertificateController` in admin.
- **skipped**: the internal routes whose only caller is entity-processor, which is retired. Checked
  by searching every caller (Java Feign interfaces and their users, the Rust crates, nocode-ai,
  the UI): each is declared in `IFeignSecurityService` but called only from entity-processor, or
  not at all.

Four internal routes have no caller today but are part of the Feign surface other services
compile against, so they are ported: `users/internal/clients/batch`, `app/profiles/internal/users`,
`clients/internal/clientIdsOfManager`, `clients/internal/query`.

## Routes per unit

### security-auth (13)

| Method | Path (under `/api/security`) |
|---|---|
| POST | `/authenticate` |
| POST | `/authenticate/otp/generate` |
| POST | `/authenticate/social` |
| GET | `/authenticateWithOneTimeToken/{pathToken}` |
| POST | `/internal/makeOneTimeToken` |
| GET | `/internal/securityContextAuthentication` |
| POST | `/internal/tokens/cleanup` |
| POST | `/makeOneTimeToken` |
| GET | `/refreshToken` |
| GET | `/revoke` |
| GET | `/securityContextAuthentication` |
| POST | `/user/access` |
| GET | `/verifyToken` |

### security-internal (55)

| Method | Path (under `/api/security`) | Java controller | Open to anonymous |
|---|---|---|---|
| GET | `/app/profiles/internal/users` | ProfileController | yes |
| GET | `/applications/internal/appCode/{appCode}` | AppController | yes |
| GET | `/applications/internal/appInheritance` | AppController | yes |
| GET | `/applications/internal/appStatus/{appCode}` | AppController | yes |
| GET | `/applications/internal/dependencies` | AppController | yes |
| GET | `/applications/internal/explicitInfo/{appCode}` | AppController | yes |
| GET | `/applications/internal/hasReadAccess` | AppController | yes |
| GET | `/applications/internal/hasWriteAccess` | AppController | yes |
| GET | `/applications/internal/writeAccessClientCodes` | AppController | yes |
| GET | `/clients/internal` | ClientController | yes |
| POST | `/clients/internal/activeClientCodes` | ClientController | yes |
| POST | `/clients/internal/batch` | ClientController | yes |
| GET | `/clients/internal/clientHierarchy` | ClientController | yes |
| GET | `/clients/internal/clientHierarchyCodes` | ClientController | yes |
| GET | `/clients/internal/clientIdsOfManager` | ClientController | yes |
| POST | `/clients/internal/clientIdsOfManagers` | ClientController | yes |
| POST | `/clients/internal/clients/denorm/full` | ClientController | yes |
| GET | `/clients/internal/doesClientManageClient` | ClientController | yes |
| GET | `/clients/internal/doesClientManageClientCode` | ClientController | yes |
| POST | `/clients/internal/filterManagedClientCodes` | ClientController | yes |
| GET | `/clients/internal/getClientByCode` | ClientController | yes |
| GET | `/clients/internal/getClientById` | ClientController | yes |
| GET | `/clients/internal/getClientNAppCode` | ClientController | yes |
| GET | `/clients/internal/getClientNAppCodeNType` | ClientController | yes |
| GET | `/clients/internal/isUserClientManageClient` | ClientController | yes |
| GET | `/clients/internal/isUserPartOfHierarchy` | ClientController | yes |
| GET | `/clients/internal/managingClientIds` | ClientController | yes |
| POST | `/clients/internal/query` | ClientController | yes |
| GET | `/clients/internal/validateClientCode` | ClientController | yes |
| GET | `/clients/internal/{id}` | ClientController | yes |
| GET | `/clienturls/internal/applications/property/url` | ClientUrlController | yes |
| GET | `/clienturls/internal/draft/token/resolve` | ClientUrlController | yes |
| GET | `/internal/billing/ai-allowed` | InternalBillingController | yes |
| POST | `/internal/billing/charge` | InternalBillingController | yes |
| POST | `/internal/billing/charge-ai` | InternalBillingController | yes |
| GET | `/internal/billing/hosting` | InternalBillingController | yes |
| GET | `/internal/billing/instructions` | InternalBillingController | yes |
| POST | `/internal/billing/meter/security` | InternalBillingController | yes |
| POST | `/internal/billing/reconcile` | InternalBillingController | yes |
| GET | `/internal/billing/serving-status` | InternalBillingController | yes |
| POST | `/internal/contactCodes` | Rust only (contact codes for core's SendContactCode) | yes |
| POST | `/internal/contactCodes/verify` | Rust only (core's VerifyContactCode) | yes |
| DELETE | `/internal/cache` | SecurityCacheController | no |
| GET | `/internal/cache` | SecurityCacheController | no |
| GET | `/internal/cache/stats` | SecurityCacheController | no |
| DELETE | `/internal/cache/{cacheName}` | SecurityCacheController | no |
| GET | `/ssl/internal/certificates` | SSLCertificateController | no (and SYSTEM only) |
| GET | `/users/internal` | UserController | yes |
| GET | `/users/internal/adminEmails` | UserController | yes |
| POST | `/users/internal/batch` | UserController | yes |
| POST | `/users/internal/clients/batch` | UserController | yes |
| POST | `/users/internal/notification` | UserController | yes |
| GET | `/users/internal/ownerEmails` | UserController | yes |
| POST | `/users/internal/processor` | UserController | yes |
| POST | `/users/internal/query` | UserController | yes |
| GET | `/users/internal/{id}` | UserController | yes |
| GET | `/users/internal/{userId}/sub-org` | UserController | yes |

`users/internal/processor` stays although its name says entity-processor: core's
`GetUsersForDistribution` calls it.

### Skipped: entity-processor only (11)

| Method | Path (under `/api/security`) | Java controller |
|---|---|---|
| GET | `/app/profiles/internal` | ProfileController |
| GET | `/app/profiles/internal/{id}` | ProfileController |
| POST | `/clients/internal/clients/denorm/delta` | ClientController |
| GET | `/clients/internal/managedClient` | ClientController |
| GET | `/departments/internal` | DepartmentController |
| GET | `/departments/internal/{id}` | DepartmentController |
| GET | `/designations/internal` | DesignationController |
| GET | `/designations/internal/{id}` | DesignationController |
| GET | `/users/internal/clients` | UserController |
| POST | `/users/internal/recordAudience` | UserController |
| POST | `/users/internal/{userId}/processor` | UserController |

### security-admin (223)

Grouped by path; every route is under `/api/security`.

- `/app` (6): POST `/app/profiles`, PUT `/app/profiles`, DELETE `/app/profiles/{id}`, GET `/app/profiles/{id}`, POST `/app/profiles/{id}/restrictClient/{clientId}`, GET `/app/{appId}/profiles`
- `/appRegIntegration` (5): GET `/appRegIntegration`, POST `/appRegIntegration`, POST `/appRegIntegration/query`, DELETE `/appRegIntegration/{id}`, GET `/appRegIntegration/{id}`
- `/applications` (30): GET `/applications`, POST `/applications`, POST `/applications/accessible/query`, GET `/applications/appCode/{appCode}`, GET `/applications/applyAppCodePrefix`, GET `/applications/applyAppCodeSuffix`, GET `/applications/clientHasReadAccess`, GET `/applications/clients/{appCode}`, GET `/applications/dependencies`, DELETE `/applications/dependency`, POST `/applications/dependency`, DELETE `/applications/everything/{id}`, GET `/applications/findAnyApps`, GET `/applications/findBaseClientCode/{applicationCode}`, GET `/applications/hasDeleteAccess`, DELETE `/applications/property`, GET `/applications/property`, POST `/applications/property`, DELETE `/applications/property/{propertyId}`, POST `/applications/query`, POST `/applications/reg/{appCode}/{urlPart}`, POST `/applications/reg/{appCode}/{urlPart}/query`, DELETE `/applications/reg/{urlPart}/{id}`, DELETE `/applications/{id}`, GET `/applications/{id}`, PATCH `/applications/{id}`, PUT `/applications/{id}`, DELETE `/applications/{id}/access`, PATCH `/applications/{id}/access`, POST `/applications/{id}/access`
- `/authorities` (1): POST `/authorities/parse`
- `/billing` (5): POST `/billing/purchase`, POST `/billing/purchase/order`, POST `/billing/quote`, POST `/billing/razorpay/webhook`, POST `/billing/repay`
- `/billing-bundles` (9): GET `/billing-bundles`, POST `/billing-bundles`, GET `/billing-bundles/config/{billingConfigId}`, POST `/billing-bundles/query`, GET `/billing-bundles/serving`, DELETE `/billing-bundles/{id}`, GET `/billing-bundles/{id}`, PATCH `/billing-bundles/{id}`, PUT `/billing-bundles/{id}`
- `/billing-configs` (8): GET `/billing-configs`, POST `/billing-configs`, GET `/billing-configs/app/{appId}`, POST `/billing-configs/query`, DELETE `/billing-configs/{id}`, GET `/billing-configs/{id}`, PATCH `/billing-configs/{id}`, PUT `/billing-configs/{id}`
- `/billing-profile` (2): GET `/billing-profile`, PUT `/billing-profile`
- `/client-activities` (3): POST `/client-activities`, GET `/client-activities/{clientId}`, POST `/client-activities/{clientId}/query`
- `/client-managers` (6): POST `/client-managers/migrateTo/{uid}`, POST `/client-managers/{clientId}`, PUT `/client-managers/{clientId}/managers`, GET `/client-managers/{uid}`, DELETE `/client-managers/{uid}/{clientId}`, POST `/client-managers/{uid}/{clientId}`
- `/clientOtpPolicy` (8): GET `/clientOtpPolicy`, POST `/clientOtpPolicy`, GET `/clientOtpPolicy/codes/policy`, POST `/clientOtpPolicy/query`, DELETE `/clientOtpPolicy/{id}`, GET `/clientOtpPolicy/{id}`, PATCH `/clientOtpPolicy/{id}`, PUT `/clientOtpPolicy/{id}`
- `/clientPasswordPolicy` (8): GET `/clientPasswordPolicy`, POST `/clientPasswordPolicy`, GET `/clientPasswordPolicy/codes/policy`, POST `/clientPasswordPolicy/query`, DELETE `/clientPasswordPolicy/{id}`, GET `/clientPasswordPolicy/{id}`, PATCH `/clientPasswordPolicy/{id}`, PUT `/clientPasswordPolicy/{id}`
- `/clientPinPolicy` (8): GET `/clientPinPolicy`, POST `/clientPinPolicy`, GET `/clientPinPolicy/codes/policy`, POST `/clientPinPolicy/query`, DELETE `/clientPinPolicy/{id}`, GET `/clientPinPolicy/{id}`, PATCH `/clientPinPolicy/{id}`, PUT `/clientPinPolicy/{id}`
- `/clients` (19): GET `/clients`, POST `/clients`, POST `/clients/appRegister`, GET `/clients/makeClientActive`, GET `/clients/makeClientInActive`, POST `/clients/noMapping`, POST `/clients/query`, POST `/clients/register`, GET `/clients/register/events`, POST `/clients/register/otp/generate`, POST `/clients/register/otp/verify`, POST `/clients/socialRegister`, GET `/clients/socialRegister/callback`, GET `/clients/socialRegister/evoke`, POST `/clients/socialRegister/evoke`, DELETE `/clients/{id}`, GET `/clients/{id}`, PATCH `/clients/{id}`, PUT `/clients/{id}`
- `/clienturls` (11): GET `/clienturls`, POST `/clienturls`, GET `/clienturls/draft`, POST `/clienturls/draft`, POST `/clienturls/draft/token`, POST `/clienturls/draft/token/extend`, GET `/clienturls/fetchUrls`, POST `/clienturls/query`, GET `/clienturls/urls`, DELETE `/clienturls/{id}`, GET `/clienturls/{id}`
- `/departments` (7): GET `/departments`, POST `/departments`, POST `/departments/query`, DELETE `/departments/{id}`, GET `/departments/{id}`, PATCH `/departments/{id}`, PUT `/departments/{id}`
- `/designations` (7): GET `/designations`, POST `/designations`, POST `/designations/query`, DELETE `/designations/{id}`, GET `/designations/{id}`, PATCH `/designations/{id}`, PUT `/designations/{id}`
- `/invoices` (5): GET `/invoices`, GET `/invoices/my`, POST `/invoices/query`, GET `/invoices/{id}`, GET `/invoices/{id}/documents`
- `/otp` (2): POST `/otp/generate`, POST `/otp/verify`
- `/rolev2` (11): GET `/rolev2`, POST `/rolev2`, GET `/rolev2/assignable/{appCode}`, POST `/rolev2/query`, DELETE `/rolev2/{id}`, GET `/rolev2/{id}`, PATCH `/rolev2/{id}`, PUT `/rolev2/{id}`, GET `/rolev2/{id}/subRoles`, DELETE `/rolev2/{roleId}/subRoles/{subRoleId}`, POST `/rolev2/{roleId}/subRoles/{subRoleId}`
- `/ssl` (12): GET `/ssl`, POST `/ssl`, GET `/ssl/certificate`, POST `/ssl/external`, POST `/ssl/internal/renew-certificates`, POST `/ssl/query`, DELETE `/ssl/request`, GET `/ssl/request`, GET `/ssl/request/challenge`, POST `/ssl/request/challenges`, GET `/ssl/token/{token}`, DELETE `/ssl/{id}`
- `/transports` (2): POST `/transports/createAndApply`, GET `/transports/makeTransport`
- `/users` (41): GET `/users`, POST `/users`, POST `/users/acceptInvite`, POST `/users/acceptRequest`, GET `/users/exists`, POST `/users/findUserClients`, POST `/users/invite`, DELETE `/users/invite/{code}`, GET `/users/inviteDetails/{code}`, GET `/users/invites`, POST `/users/invites/query`, PATCH `/users/makeUserActive`, PATCH `/users/makeUserInActive`, GET `/users/members`, POST `/users/noMapping`, POST `/users/query`, POST `/users/rejectRequest/{requestId}`, GET `/users/request`, POST `/users/request`, GET `/users/requestUser/{requestId}`, GET `/users/requests`, POST `/users/requests/query`, POST `/users/reset/password`, POST `/users/reset/password/otp/generate`, POST `/users/reset/password/otp/verify`, GET `/users/sub-org`, POST `/users/unblockUser`, POST `/users/updatePassword`, DELETE `/users/{id}`, GET `/users/{id}`, PATCH `/users/{id}`, PUT `/users/{id}`, GET `/users/{userId}/app/{appId}/assignedProfiles`, GET `/users/{userId}/assignProfile/{profileId}`, GET `/users/{userId}/assignRole/{roleId}`, PUT `/users/{userId}/designation/{designationId}`, GET `/users/{userId}/removeProfile/{profileId}`, GET `/users/{userId}/removeRole/{roleId}`, DELETE `/users/{userId}/reportingManager`, PUT `/users/{userId}/reportingManager/{managerId}`, POST `/users/{userId}/updatePassword`
- `/wallets` (7): GET `/wallets`, POST `/wallets/credit`, GET `/wallets/lookup`, GET `/wallets/plan`, GET `/wallets/status`, GET `/wallets/transactions`, POST `/wallets/{walletId}/adjust`

## Porting security-admin in parallel

Three pieces, each a module under `src/admin/` with its own router function that the
security-admin binary merges, all on the shared data layer below. Each piece adds its own
`data/<area>.rs` files rather than growing the shared ones, so the pieces rarely touch the same
file; `dto.rs` changes go through piece 1 (which adds the `Profile` DTO).

1. **Users and organisation** (81 routes): `UserController` (users, invites, requests, password
   reset, sub-org, members), `ProfileController`, `RoleV2Controller`, `DesignationController`,
   `DepartmentController`, `ClientManagerController`, `OtpController`,
   `AuthorityExpressionController`. Brings the profile read with its arrangement merge
   (`ProfileDAO.readRootProfile` + `DifferenceApplicator`), which also lets security-internal
   answer `?fetchProfiles`. Events (`UserService`, `UserInviteService`) through
   `crates/connections`' publisher.
2. **Clients, apps and hosting** (106): `ClientController` (CRUD, registration, social
   registration, activation), `AppController` with app CRUD, access, properties and dependencies,
   `AppRegistrationController` and the registration integrations, `ClientUrlController` (URLs,
   draft hosts and tokens), `SSLCertificateController` (ACME requests and renewal, Cloudflare
   custom hostnames), the three client policy controllers, `ClientActivityController`,
   `TransportController`. Files' `internal/accesspath` (registration) through a platform
   `Upstream`.
3. **Billing** (36): billing bundles, billing configs, billing profile, bundle purchase (quote,
   order, Razorpay webhook, repay), invoices (documents through files' `internal/secured/createKey`),
   wallets. Extends `data/billing.rs` and the wallet rules security-internal already has.

## The shared library

Both binaries (and admin later) are thin `main`s over this crate. What they share:

- **The caller's context** (`context.rs`): Java's `JWTTokenFilter` runs on every request of every
  controller, so every unit computes the context the same way, through the same caches.
- **Models in Jackson's shape** (`model.rs`, `dto.rs`, `data/*`): `Client`, `User`, `App`, `Designation`,
  `ClientHierarchy`, `ClientUrlPattern`, billing records, each written in Jackson's property order
  with `NON_EMPTY`.
- **DAOs** (`data/*`): the Java DAO SQL, in sqlx. The `AbstractDAO` filter language
  (`condition.rs`) and its per-DAO overrides (`UserDAO`'s `profile.*` / `appId` / `appCode`,
  `ClientDAO`'s `user.*` / `appId` / `appCode`) and the context restrictions the DAOs add
  (`ClientCheckDAOHelper`, `ClientDAO.filter`, `UserDAO.filter`).
- **Caches** (`caches.rs`): Java's cache names and key concatenations, L1 only, evictions both ways
  on `evictionChannel` (prefix `cmn`). A Rust write publishes and deletes the Redis entry, exactly
  as Java's `CacheService.evict` does, so Java drops its copy too.
- **Events**: `crates/connections`' RabbitMQ publisher (`EventCreationService`'s message shape).
  Locally off, or pointed at a scratch exchange; never the real `events` exchange while Java
  consumes it.
- **Other services**: files through a platform `Upstream` (only admin needs it: invoices and app
  registration).

## A Flyway-compatible migration runner (not built)

Java security owns the schema: Spring Boot runs Flyway at start-up over
`security/src/main/resources/db/migration` (88 files, `V1__...sql` to `V88__...sql`; the local
database has 85 applied). When Java security is retired, a Rust unit (or a separate job) has to take
that over without disturbing `flyway_schema_history`. What it needs:

- **Read the history table** as Flyway writes it: `installed_rank` (int, PK, the apply order),
  `version` (varchar, null for repeatable migrations), `description`, `type` (`SQL`), `script`
  (file name), `checksum` (int), `installed_by`, `installed_on`, `execution_time` (ms), `success`
  (tinyint).
- **Versions**: parse `V<version>__<description>.sql`; versions compare part by part as numbers
  (`1.10` after `1.9`), not as strings. The description is the name with `_` turned into spaces.
- **Checksums**: Flyway's CRC32 over the script read line by line: a UTF-8 BOM stripped, each
  line's terminator dropped (so CRLF and LF files agree), the CRC updated with each line's UTF-8
  bytes, the result stored as a signed 32-bit int. A runner must reproduce it exactly or every
  existing row fails validation.
- **Validate** before migrating: every applied version must still exist with the same checksum and
  description; a failed row (`success = 0`) stops everything until repaired; pending versions
  older than the latest applied are an error unless out-of-order is allowed (Java uses the
  default: not allowed).
- **Apply**: one migration at a time in version order, each in its own transaction where MySQL
  allows (DDL commits implicitly in MySQL, so a failed DDL migration leaves partial changes: Flyway
  records `success = 0` and so must the runner), then the history row with the next
  `installed_rank`, the measured `execution_time` and `installed_by` = the database user.
- **Statement splitting**: the scripts contain several statements, `DELIMITER` changes for
  procedures and triggers, and comments; MySQL's protocol runs one statement at a time, so the
  runner needs Flyway's MySQL parser behaviour (or multi-statement mode with care for `DELIMITER`).
- **Locking**: Flyway takes `GET_LOCK('flyway-<crc of the table>', ...)` (a MySQL named lock) so two
  instances starting together do not both migrate; the runner must take the same lock so it also
  excludes a Java instance still starting during the switch.
- **Baseline**: not used here (the history starts at V1), but `baselineOnMigrate` rows have type
  `BASELINE` and must be skipped by validation.
- **Connection**: Flyway runs over JDBC with its own credentials (`spring.flyway.*`, separate from
  the R2DBC pool); the runner should take the same separate user if production keeps DDL rights
  away from the application user.
