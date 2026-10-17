# The overridable write path

The write side of commons-mongo's overridable-document engine, as a library. crates/ui and
crates/core mount it for their document kinds. Nothing here is mounted on its own.

## Java to Rust

| Java (commons-mongo unless noted) | Rust |
|---|---|
| `AbstractMongoDataService`, `AbstractMongoUpdatableDataService`, `AbstractOverridableDataService` (create, read, update, updateBlueprint, delete, access checks, merge, evictions, createForClient, updatedBaseAppCode, deleteEverything) | `write::service` (`Commons`, `OverridableService<K>`) |
| the same class, draft half (saveDraft, forkForCaller, readDraftWithVersion, publish, reconcile, markPublished, discardDraft, createUnpublished) | `write::draft` (with `store::Store::reconcile`) |
| the same class, list half (readPageFilterLRO, readIndexLRO, readForTransport, readToTransport) | `write::list` |
| subclass overrides (`updatableEntity`, `create`, `update`, `delete`, `evictDraft`, `evictRecursively`, `getAccessCheckName`, `isVersionable`, `getTransportDependencies`, ...) | `write::kind::Kind` hooks |
| `AbstractDraftService`, `Draft` | `write::draft::DraftStore`, `DRAFT` |
| `AbstractVersionService`, `Version` | `write::version::VersionStore`, `VERSION` |
| `AbstractPublishService` | `write::publish::PublishService` |
| `AbstractTransportService`, `Transport`, `TransportRequest`, `TopologicalUtil` | `write::transport`, `write::topo` |
| `AbstractDeletionService` | `write::deletion::DeletionService` |
| `AbstractFillerService`, `AbstractFiller` (ui `UIFiller`, core `CoreFiller`) | `write::filler::Filler` |
| the controllers (`AbstractOverridableDataController` and its bases, `AbstractVersionController`, `AbstractPublishController`, `AbstractTransportController`, ui/core `DeletionController`) | `write::controller` (request to `Reply`), `write::router` (axum) |
| `AbstractMongoDataService.filter`, `FilterCondition`, `ComplexCondition`, `AbstractConditionDeserializer`, `Query` | `write::condition` |
| Spring `Pageable`, `Sort`, `PageImpl` JSON, `SortSerializationModule` | `write::spring` |
| `AbstractMongoMessageResourceService` and the ui and core `messages_en.properties` | `write::messages` |
| `SchemaRefs` | `write::schema_refs` |
| Spring Data writing a document (`_id`, field order, `__d-o-t__`, dates) | `write::persist` |
| `ReactiveMongoTemplate`/repositories, `FeignAuthenticationService`/`IFeignSecurityService`, `InheritanceService` | `backend` (`Backend`, `Directory`, Mongo and in-memory implementations) |

## Setting it up

```rust
use overridable::write::{Commons, Messages, OverridableService};
use overridable::write::version::UI_AUTH_NAMES; // CORE_AUTH_NAMES for core

let store = overridable::Store::new(db, security.clone(), &cache);     // cache prefix "cmn"
let cx = Commons::new(store, cache.clone(), Messages::ui(), UI_AUTH_NAMES); // Messages::core() for core
let pages = OverridableService::new(PageKind::new(&cache), cx.clone());
```

`Store::with_parts(Arc<dyn Backend>, Arc<dyn Directory>, &cache)` builds the same thing on other
parts. Tests use `backend::MemBackend` and `backend::FakeDirectory`, both public so the mounting
crates can test with them too.

The caller is a `platform::security::ContextAuthentication` whose `url_client_code` and
`url_app_code` are set from the request's `clientCode`/`appCode` headers.
`SecurityClient::context_authentication` already does that, and so does `router::SecurityCallers`.

## OverridableService<K>

All methods take `&ContextAuthentication` and answer `AppResult<_>` (Java's statuses and
messages). An entity is a `JMap` holding every field of the kind's `Pojo`. Use
`pojo::convert_json` for a request body and `pojo::to_jackson` for a response.

| Method | Java | Answers |
|---|---|---|
| `create(ca, entity)` | `create` | the created object, merged (read back) |
| `read(ca, id)` | `read(id)` | merged; 404 when missing or refused |
| `read_internal(id)` | `readInternal(id)` | merged, no access check |
| `read_resolved(ca, name, app, client, draft)` | `read(name, app, client)` up to `applyChange`, for the client `servedClientCode` picks (a signed-in tenant's own on a shared host, commit e2b7d48aa) | `Arc<Resolved>`, cached per served client and surface |
| `update(ca, entity)` | `update` | merged; 403 refused or unknown id, 412 stale version |
| `update_blueprint(ca, id, Option<JMap>)` | `updateBlueprint` | the stored document |
| `delete(ca, id)` | `delete` | `true`; 404 missing or no access, 403 while overridden |
| `save_draft(ca, entity, Option<i64>)` | `saveDraft(entity, expectedDraftVersion)` | the `Draft` |
| `read_draft_with_version(ca, id)` | `readDraftWithVersion` | `(entity, draft version or 0)` |
| `fork_for_caller(ca, id)` | `forkForCaller` | the caller's own row |
| `publish(ca, id, Option<&str>)` | `publish` | merged result |
| `discard_draft(ca, id)` | `discardDraft` | whether a draft was there |
| `create_unpublished(ca, entity)` | `createUnpublished` | created, `published: false` |
| `create_for_client(ca, id, client)` | `createForClient` | `None` for an unknown id |
| `fork_for_client(ca, base, client)` | `forkForClient` | never-published derived copy |
| `read_page_filter_lro(ca, eager, client_only, &Pageable, &Params)` | `readPageFilterLRO` | `LroPage` (`.to_json(&pageable)`) |
| `read_index_lro(ca, app, Option<client>)` | `readIndexLRO` | `LroPage` |
| `read_for_transport` / `read_to_transport` | same | objects / `(version, id)` |
| `updated_base_app_code(ca, app, new_base, client)` | `updatedBaseAppCode` | bool |
| `delete_everything(ca, app, client)` | `deleteEverything` | `None` without write access |
| `access_check(ca, Method, app, client, write)` | `accessCheck` (a refused READ re-checked as a write, commit 13470b2f1; a write for another client needs that client's write access to the app too, commit 3cf6ebc54) | bool |
| `evict_recursively(app, client, name)`, `evict_draft(...)` | same | |

`OverridableService<K>` also implements `write::AnyService`, the type-erased form that
`PublishService`, `DeletionService` and `TransportService` take in their service lists.

## Plugging in a document kind

A kind is a `store::DocType` (read path: names, collection, `Pojo`, `apply_override`,
`extract_difference`, `cache_name`, `draftable`) plus `write::Kind` (write path hooks, all with
the base class's behaviour as their default):

| Hook | Runs | Java it stands for |
|---|---|---|
| `access_check_name()` | | `getAccessCheckName()` (URIPath and the fillers return `Application`) |
| `versionable()` | | `isVersionable()` (Personalization: false) |
| `snapshot_is_override()` | | whether `extractDifference` mutates in place, as nearly every class's does |
| `delete_reads_first()` | | the subclass `delete` starts with `this.read(id)` |
| `access_override(ca, method)` | before every access check | `PersonalizationService.accessCheck` |
| `before_create(cx, ca, &mut entity)` | start of `create` | Application name rule, filler name, URIPath name and validation, Function/Schema namespace name, Storage uniqueName |
| `after_create(cx, &created)` | end of `create` (and every fork) | URIPath `URIPatternCache`, filler `FILLER_READ`, Storage `_index_creation` |
| `before_update(cx, ca, &mut entity)` | start of `update`, on the body | URIPath `validateURIPath`; Transport refuses (304) |
| `updatable_precheck(cx, ca, &existing, &incoming)` | `updatableEntity`, before the version check | Personalization's owner check |
| `updatable_fill(cx, ca, &mut existing, &incoming)` | `updatableEntity`, after the check and the version bump | the field copies; Page component versions; Function/Schema name checks; Storage validate |
| `after_update(cx, &request, &saved)` | end of `update` (so every publish) | the ui OUI/SSR evictions, Style/Theme/Page OUI, Application index/manifest/properties, URIPath pattern, Storage `_index_creation`/`_table_creation` |
| `before_delete(cx, ca, &stored)` | before the base delete | Personalization's owner check |
| `after_delete(cx, &deleted, result)` | after the base delete; may replace the answer | the ui OUI/SSR evictions (Page/Style/Theme answer the SSR result) |
| `after_evict_recursively(cx, app, client, name)` | end of `evictRecursively` | Schema and Storage table rebuilds, `storageReferences` |
| `after_evict_draft(cx, app, client, name)` | end of `evictDraft` | ui OUI/SSR, Application caches, URIPath pattern |
| `after_delete_everything(cx, app, client)` | end of `deleteEverything` | Application caches; core `dropDraftData` |
| `after_read(cx, ca, entity)` | end of `read(id)` | Connection hides credentials |
| `transport_dependencies(&e)` / `strip_transport_dependencies(&e)` | transport import | Schema `SchemaRefs.collect`, Storage relations |

`Commons` gives hooks `evict_all(name)`, `evict(name, key)`, `publish(channel, message)` (the
ui SSR invalidation: `publish("ssr:cache:invalidation", "{\"appCode\":\"<app>\"}")`), `error(...)`,
`store`, `drafts` and `versions`.

Example: a Style kind as ui's `StyleService` has it.

```rust
pub struct StyleKind;

impl overridable::DocType for StyleKind {
    fn object_name(&self) -> &'static str { "Style" }
    fn collection(&self) -> &'static str { "style" }
    fn pojo(&self) -> &'static Pojo { &STYLE }
    fn apply_override(&self, this: JMap, _base: &JMap) -> Option<JMap> { Some(this) }
}

#[async_trait]
impl overridable::write::Kind for StyleKind {
    fn delete_reads_first(&self) -> bool { true }
    async fn updatable_fill(&self, _cx: &Commons, _ca: &ContextAuthentication, existing: &mut JMap, incoming: &JMap) -> AppResult<()> {
        existing.insert("styleString".into(), incoming.get("styleString").cloned().unwrap_or_default());
        Ok(())
    }
    async fn after_update(&self, cx: &Commons, request: &JMap, _saved: &JMap) -> AppResult<()> {
        let app = str_field(request, "appCode").unwrap_or("null"); // Java keys on the body's app
        for c in ["applicationOUICache", "pageOUICache", "styleOUICache"] {
            cx.evict_all(&format!("{c}-{app}")).await;
        }
        cx.publish("ssr:cache:invalidation", &format!("{{\"appCode\":\"{app}\"}}")).await;
        Ok(())
    }
    async fn after_evict_draft(&self, cx: &Commons, app: &str, _c: &str, _n: &str) -> AppResult<()> { /* the same three and SSR */ Ok(()) }
    async fn after_delete(&self, cx: &Commons, deleted: &JMap, _r: bool) -> AppResult<bool> { /* the same; answer the SSR publish */ Ok(true) }
}
```

Then mount it:

```rust
let callers: Arc<dyn CallerSource> = Arc::new(SecurityCallers { security, server_port });
let styles = OverridableService::new(StyleKind, cx.clone());
let router = Router::new()
    .merge(write::router::overridable_router("/api/ui/styles", styles.clone(), callers.clone()))
    .merge(write::router::version_router("/api/ui/versions", cx.versions.clone(), callers.clone()))
    .merge(write::router::publish_router("/api/ui/publish", Arc::new(PublishService::new(cx.clone(), services.clone())), callers.clone()))
    .merge(write::router::deletion_router("/api/ui", Arc::new(DeletionService::new(cx.directory().clone(), services.clone())), callers.clone()))
    .merge(write::router::transport_router("/api/ui/transports", Arc::new(TransportService::new(cx.clone(), services, "ui", "umodl")), callers));
```

A unit with its own routing can call the `write::controller` functions directly. They take the
caller, path values, a `spring::Params` of the query and the body bytes, and answer a `Reply`
(status, headers, `Json`/`File`/`Empty`). `Reply` implements `IntoResponse`, writing JSON as
the Java services do: indented, with Spring Security's headers.

Routes per controller (relative to the base path):

| Router | Routes |
|---|---|
| `overridable_router` | `GET ""` list; `POST ""` create (`?draft=true` create-unpublished); `GET/POST /nomap2` 400; `GET /{id}` (`?draft=true`: draft and `X-Draft-Version`); `PUT /{id}` (`?draft=true[&draftVersion=n]`: save draft; `draft=false`: 400); `DELETE /{id}`; `PATCH /{id}/blueprint`; `GET /createForClient/{id}/{clientCode}`; `POST /{id}/fork`; `POST /{id}/publish?message=`; `DELETE /{id}/draft` |
| `version_router` | `GET /{id}`, `POST /{id}/query` |
| `publish_router` | `GET /app/{appCode}/pending?clientCode=`, `POST /app/{appCode}?clientCode=` |
| `deletion_router` | `DELETE ?deleteAppCode=` (needs `X-Forwarded-Host`, `X-Forwarded-Port`, `clientCode`, `appCode`) |
| `transport_router` | the overridable routes (plain `POST` refused) plus `POST /makeTransport`, `POST /internal/makeTransport`, `GET /applyTransport/{id}`, `GET /applyTransportCode/{code}`, `POST /internal/cleanupOlderThan`, `GET /transportTypes`, `POST /internal/createAndApply?fileName=`, `POST /createAndApply` (multipart `file`) |

The Java base paths are:

| Module | Paths |
|---|---|
| ui | `api/ui/{applications,pages,styles,themes,uripaths,filler,functions,schemas,transports,versions,publish}`, deletion at `api/ui` |
| core | `api/core/{storages,schemas,functions,connections,templates,notifications,eventDefinitions,eventActions,workflows,filler,transports,versions,publish}`, `api/core/workflow/actions`, deletion at `api/core` |

The service lists Java uses:

| Module | List | Services, in order |
|---|---|---|
| ui | publish | application, page, style, theme, function, schema, uriPath, filler |
| ui | deletion | app, page, style, theme, function, schema, filler, uriPath, transport |
| ui | transport | app, page, style, theme, function, schema, filler, uriPath (`"ui"`, `"umodl"`) |
| core | publish | storage, connection, template, notification, eventDefinition, eventAction, action, workflow, function, schema, filler |
| core | deletion | action, template, storage, function, schema, eventAction, eventDefinition, filler, connection, transport, workflow |
| core | transport | schema, storage, function, template, eventDefinition, eventAction, filler (`"core"`, `"cmodl"`) |

## Evictions

Cache names are the Java names. Each one is evicted through the platform `CacheService` with
prefix `cmn`:

- `evictAll` drops the local copy, publishes `cmn-<cache>:*` on `evictionChannel`, and runs
  `DEL cmn-<cache>` on Redis.
- `evict` drops the local copy, publishes `cmn-<cache>:<key>`, and runs `HDEL cmn-<cache> <key>`.

These are exactly what Java's `CacheService.evictAll` / `evict` do. `<O>` is the object name and
`<Cache>` is `getCacheName`: `<O>Cache_<app>_<name>` unless the kind overrides it (`UIFillerCache_`,
`URIPathCache_<app>_URICache_<app><name>`, `UIFunctionCache_`, `UISchemaCache_`).

### The base class (every kind; done by this crate)

| Write | Java evicts | Rust evicts |
|---|---|---|
| create, createForClient, fork (forkForCaller's fork, forkForClient), a transport import's create | evictAll `<Cache>(app,name)`, `<Cache>(app,name)_DRAFT`, `<Cache>(app,<O>)_READ_PAGE` | the same, then `after_evict_recursively`, `after_create` |
| update, publish (which updates), a transport import's update | the same three | the same, then `after_evict_recursively`, `after_update` |
| updateBlueprint | the same three | the same |
| publish of a never-published object (markPublished) | the same three again | the same |
| saveDraft, forkForCaller, discardDraft | evictAll `<Cache>(app,name)_DRAFT` | the same, then `after_evict_draft` |
| delete | evict `<Cache>(app,name)` key `<client>`, evict `<Cache>(app,name)_DRAFT` key `<client>`, evictAll `..._READ_PAGE`; the draft is discarded | the same, then `after_delete` |
| deleteEverything | evictAll `..._READ_PAGE`; per name `evictAll <Cache>(app,n)` built but never subscribed (only the local clear and the publish happen, never the `DEL`); `_DRAFT` never | evictAll `..._READ_PAGE`, and per name evictAll `<Cache>(app,n)` and `<Cache>(app,n)_DRAFT`, then `after_delete_everything` |
| updatedBaseAppCode | nothing | nothing |
| a filler's create, update, delete | evictAll `<Cache>(app,app)_FILLER_READ` (keyed on the body's app on update) | the same (keyed on the stored app); also on evictDraft |

### What the mounting crates' hooks must evict (from the Java subclasses)

| Kind | Write | Java evicts | Hook |
|---|---|---|---|
| ui Application, Page, Style, Theme (via `AbstractUIOverridableDataService`) | update | evictAll `applicationOUICache-<app>`, `pageOUICache-<app>`, SSR publish `ssr:cache:invalidation` `{"appCode":..}`; `<app>` is the **body's** | `after_update` |
| same | evictDraft | the same three, the object's app | `after_evict_draft` |
| same | delete | the same three, the stored app | `after_delete` |
| Page | update / delete | + `pageOUICache-<app>` (delete answers the SSR result) | `after_update` / `after_delete` |
| Style | update, evictDraft, delete | + `styleOUICache-<app>` | |
| Theme | update, evictDraft, delete | + `themeOUICache-<app>`, `styleOUICache-<app>` | |
| Application | update, evictDraft, delete, deleteEverything | `ApplicationCache_<app>_indexNewCache_<app>`, `ApplicationCache_<app>_manifestCache_<app>`, `ApplicationCache_<app>_cacheProperties_<app>` and `..._DRAFT`, `applicationOUICache-<app>`, SSR | the four hooks |
| URIPath | create, update, evictDraft, delete | evict `URIPatternCache` key `<app>-<client>` | `after_create`, `after_update`, `after_evict_draft`, `after_delete` |
| Storage (core) | create | evictAll `<uniqueName>_index_creation` | `after_create` |
| Storage | update | evictAll `<uniqueName>_index_creation`, `<uniqueName>_table_creation` | `after_update` |
| Storage | evictRecursively, evictDraft | evictAll `storageReferences`; per storage and its forks `<uniqueName>_storage_schema`, `<uniqueName>_storage_schema_resolved`; DDL reconcile | `after_evict_recursively`, `after_evict_draft` |
| Storage | delete | `<uniqueName>_storage_schema`, `..._resolved`; draft tables | `after_delete` |
| Schema (core) | evictRecursively, evictDraft, delete | the storage rebuild above for every storage referencing it | the same hooks |
| Function, Template, Notification, EventDefinition, EventAction, Action, Workflow, Connection, Personalization, Transport | | the base only | none |

The security caches are only read here: `appReadAccess`, `appWriteAccess` and
`byAppCodeExplicit` in `RemoteDirectory`, and `inheritanceOrder` in `Store`. They use the Java
names, so evictions from security reach them.

## Tests

- In memory (no database), run by `cargo test -p overridable`:
  - `tests/write_crud.rs`, `write_drafts.rs`, `write_services.rs`, `write_http.rs`;
  - unit tests in every module.
- Real MongoDB / Redis (gated, `#[ignore]`): `tests/write_mongo.rs` and the read path's
  `tests/store_it.rs`, run as
  `OVERRIDABLE_TEST_MONGO=1 [OVERRIDABLE_TEST_REDIS=1 MODLIX__REDIS__URL=...] cargo test -p overridable -- --include-ignored`.
  - They use only `overridable_rusttest_<epoch>_<rand>` on the local MongoDB (`tests/scratch`). It is dropped however the test ends, and leftovers over two hours old are swept.
  - The Redis test publishes under a prefix no service uses.
