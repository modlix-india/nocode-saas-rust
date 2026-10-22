# What crates/connections needs from elsewhere

The library takes what it cannot do itself through traits and plain values. Nothing here
blocks the library's tests; each item is needed before core can serve traffic with it.

## crates/core (the caller)

1. **Implementations of the traits:**

   | Trait | Java equivalent | What to implement |
   |---|---|---|
   | `connection::ConnectionStore` | `ConnectionService.readInternal(name, appCode, urlClientCode, clientCode)` | Over `crates/overridable`, on the caller's surface (draft or live). Hand in the resolved document with Mongo's escaped keys (`mail__d-o-t__smtp__d-o-t__host`) already unescaped. This crate applies the type, client and `onlyThruKIRun` rules itself. |
   | `email::TemplateStore` | `TemplateService.read` | The same overridable read, for `template` documents. |
   | `tokens::TokenStore` | `CoreTokenDAO` | Use `tokens::TokenDao::new(pool, JavaClock { zone_offset_seconds })` over the core MySQL pool. The pool must come from `platform::db::mysql_pool` (UTC sessions), and the offset must be the Java core's JVM zone for as long as both write `core_tokens` (DIFFERENCES 18). Live-tested on a scratch database (`tests/tokens_mysql.rs`). |
   | `rest::auth::AuthTokenFunction` | `coreFunctionService.execute(ns, name, app, client, null, null)` | REST_AUTH connections get their token by running a stored KIRun function, so this needs core's executor. |
   | `notification::HierarchyChecks` | `IFeignSecurityService.isUserPartOfHierarchy` and `doesClientManageClientCode` | `GET /api/security/clients/internal/isUserPartOfHierarchy?userId&clientCode` and `GET /api/security/clients/internal/doesClientManageClientCode?managingClientCode&clientCode`. `platform::security::SecurityClient` has neither (see "platform" below). |
   | `rest::call::DownloadSink` | `IFeignFilesService.create` and `doesClientManageClientCode` | Used when a `CallRequest` downloads a file: `POST /api/files/internal/{fileType}` with the bytes. |

2. **The KIRun function wrappers.** Register these with core's function repository; they call
   `rest::call::call`, `email::send_email_function`, `ai::chat_function`,
   `notification::process_and_send` and `mq::create_event`:
   - `CoreServices.REST.CallRequest`, `GetRequest`, `PostRequest`, `PutRequest`,
     `PatchRequest` and `DeleteRequest`
   - `CoreServices.Email.SendEmail`
   - `CoreServices.AI.Chat`
   - `CoreServices.Notification.SendNotification`, and the Rust-only
     `CoreServices.Notification.SendDataNotification` (`notification::prepare_data`)
   - `CoreServices.Event.CreateEvent`

   Each wrapper builds a `context::Caller` from the request context (authentication,
   URL app and client, `in_kirun`, draft, `X-Debug`).
3. **The HTTP routes.** Mount the `controller` functions under `/api/core/connections`:
   - `POST /oauth/evoke`, `GET /oauth/callback` and `GET /oauth/revoke`
   - `GET /internal/oauth2/token/{connectionName}`, `GET /internal/notification/{name}` and
     `GET /internal/{name}`

   Each function's doc gives Java's status and body. `/internal/{name}` answers the whole
   `Connection` document as the core `ObjectMapper` writes it (an `AbstractOverridableDTO`:
   the base fields, the version and audit fields, then the connection's own). `Connection`
   keeps the fields it does not model in `other`. The Jackson writing of the whole document
   is left to the route, along with the other definition documents core serves.
4. **Configuration.** Fill these from Spring Cloud Config, as Java reads them:
   - `ConnectionsConfig::block_private_targets` (`core.rest.blockPrivateTargets`, default true)
   - `java_zone_offset_seconds`
   - one `mq::Publisher` built from `spring.rabbitmq.*` (`amqp://user:pass@host:port/%2f`)
   - `mq::Route::events()` and `mq::Route::notifications()`, unless `events.mq.exchange` /
     `events.mq.routingkeys` (and the notification equivalents) are set

   Never log the AMQP URI: it carries the password.
5. **The cache eviction listener.** The OAuth2 and REST-auth token caches (`RestOAuthToken`,
   `RestAuthToken`) live in the shared `CacheService`. Core must start
   `CacheService::spawn_eviction_listener` once, so that evictions published by Java core
   instances (and by other Rust instances) drop the local copies.

## platform

1. `CacheService::evict_everywhere(cache_name, key)` was **added** in this work. It evicts one
   key locally, publishes `<prefix>-<cacheName>:<key>` on the eviction channel and deletes the
   key in Redis, as Java's `CacheService.evict` does. The change is additive, with a test
   (`evicts_one_key_everywhere`), and `cargo test -p platform` passes.
2. `SecurityClient` has no `is_user_part_of_hierarchy` or `does_client_manage_client_code`
   (the second exists only as `is_user_client_manage_client` on ids). Core can call the two
   routes itself (above), or they can be added to platform additively.

## Decisions for the owner

These Java behaviours are kept as they are (DIFFERENCES 19 to 24). Each needs a yes or no:

- Refuse REST URLs with a `{id}` path template when the guard is on.
- Send form-encoded values as JSON text.
- Return `application/*` responses as byte arrays.
- Overwrite the notification `clientCode`.
- Store client-credentials tokens under the connection's client but look them up under the
  caller's.
- Support only `OPENAI` for AI.

Two Java bugs are fixed and not kept: the SendGrid double send (7) and the Float narrowing (8).
These also need a yes from the owner, because a stored function that relied on either behaves
differently.
