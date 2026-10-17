# ui-engine, ui-shell and ui-editor: deliberate differences from the Java ui service

ui-engine serves the read routes of the Java `ui` service (`EngineController`,
`PersonalizationController`, and `repositoryFind` / `repositoryFilter` of `FunctionController`
and `SchemaController`) from the same Mongo database. ui-shell serves the rest of its request
time surface: `UniversalController` (the index page behind the hosting gate, the manifest,
`/js/dist/**`, `/apiDocs`, the URI path routes, ACME, `/hassso`, `/sso/{token}`),
`AnalyticsController` and `UICacheController`. Status codes, headers, bodies and the 304 rules
are the Java ones; `tools/parity_ui.py` and `tools/parity_ui_shell.py` check them case by case.
ui-editor serves every other ui controller (the editing surface: CRUD, drafts, fork and publish
of applications, pages, styles, themes, functions, schemas, URI paths and fillers, versions,
publish-all, transport, an app's wipe, mobile apps, the application index, page components and
events, function steps) on the `overridable` crate's write path; `tools/parity_ui_editor.py`
checks it, the evictions each write publishes included.
What follows is everything that differs on purpose, and why.

## Error bodies: coded, plain-language messages (all three units, 2026-10-17)

Every JSON error carries a stable code and a message written for the person reading it: `UI.*`
from `messages/en.toml` (`src/catalogue.rs`) for ui's own refusals, `DEF.*` for refusals on a
definition (the `overridable` crate's catalogue), and the platform's `COMMON.*`. Statuses are
Java's, unchanged; so is the 404-vs-403 split. HTML error pages ui-shell serves keep their shape.

| | Java | ui units |
|---|---|---|
| `message` | the bundle text (`Path string missing`) | the catalogue text in the request's language (`The URI path needs a path.`) |
| `debugMessage` | the same text | Java's text under its key (`[uri_path_string_null] Path string missing`); Spring's text for Spring's 400s; the cause for a 500 |
| added fields | none | `code`, `action`, `params` (the values, as words), `locale` |
| a page's permission not held | `Permission/Role <expression> is required...` | `UI.PAGE_PERMISSION_REQUIRED`, naming the permission in words when the expression is a plain one (`A` or `A or B`) |
| a URI path route's permission not held | `Authorization <expression> is required` | `UI.FORBIDDEN_EXECUTION`; an anonymous caller gets `UI.SIGN_IN_REQUIRED` ("Please sign in to continue.") |
| ui-editor `@PreAuthorize` | empty 401 (anonymous), 403 `text/plain` "Access Denied" | `COMMON.SIGN_IN_REQUIRED` / `COMMON.SIGNED_OUT` (401), `COMMON.PERMISSION_REQUIRED` naming the permission (403) |
| Spring's 400s, 415, the `ControllerAdvice` 500s | "Please try again. A server error - <id>" | `COMMON.PARAM_MISSING`, `PARAM_INVALID`, `BODY_MISSING`, `BODY_UNREADABLE`, `BODY_NOT_JSON`, `DEF.HEADER_MISSING`; `COMMON.INTERNAL_ERROR` ("Something went wrong on our side. Error id <id>: give it to support.") |
| security refusing a credential without a message | empty 401 or 403 | `COMMON.SIGNED_OUT`, same status |

- Relayed errors pass on as they come, with their status: a security refusal (its coded error
  from the Rust security units, its message from Java's; `platform::security::refusal_error`),
  a core function's error (ui-shell's URI path routes) and a route's own error answer.
- The empty bodies Java answers on purpose (`nomap2`, a body method on a redirection, a bare
  firewall 400) stay empty.

Reproduced as Java does it, so not differences: the plain `OPTIONS` answer on every path
(`200`, `Allow: DELETE,POST,GET,PUT,PATCH,HEAD,OPTIONS`, an empty `Accept-Patch`, the security
headers); CORS preflights answered inside the security chain (security headers on, no
`Access-Control-Max-Age`); Spring Security's `StrictServerWebExchangeFirewall` (a bare 400 for
an encoded slash, backslash, percent, period, semicolon, NUL, CR or LF in the path, `//`, a `.`
or `..` segment, a line or paragraph separator, a method outside the seven; a 400 after the
headers for a control character in a query parameter name); and no `WWW-Authenticate` on a 401
(nocode-saas aca9929dd; the Java build running locally predates it and still sends it).

## ETags and caching

1. **ETag ids are content digests, not random ids.** Java gives every object a random
   `shortUUID` each time its definition cache is filled, and shares it between instances through
   the Redis L2 (Java-serialized, which Rust cannot read). ui-engine derives the id from a
   SHA-256 of the merged document (22 base62 characters, same alphabet). The tag *shapes* are the
   same (`W/`, `W/d-`, `W/nlg-`, `W/dlg-`, ...) and so are the 304 rules, including Java's
   substring test and its quirks (an empty `If-None-Match` answers 304; a stale page tag gets the
   page's id back without the login prefix). Consequences:
   - a tag issued by Java is not recognised by ui-engine, and the reverse, so a browser that
     moves between the two gets one extra 200 per object;
   - every ui-engine instance agrees on an object's tag without a shared cache, and a tag only
     changes when the content does (Java's changes on every eviction and restart).
2. **The engine response caches are not kept** (`applicationOUICache-*`, `pageOUICache-*`,
   `styleOUICache-*`, `themeOUICache-*`). They are keyed by the tag the client sends and only save
   recomputing a response; every ui-engine response is computed from the definition caches,
   which are kept under the Java names (`PageCache_<app>_<name>`, `..._DRAFT`,
   `ApplicationCache_<app>_cacheProperties_<app>`, `UIFunctionCache_...`, `inheritanceOrder`, ...)
   and evicted by the Java services' messages (prefix `cmn`). Java can keep answering 304 from
   those caches after something that does not evict them changes (a role granted to a user, an
   app's login page after a security change); ui-engine answers from current data.
3. **A cold Java cache filled by two requests at once** keeps whichever random id was written
   last, so Java can hand out a tag it then does not honour. ui-engine's ids are deterministic.
   The parity script re-asks Java when this happens and reports it.
4. **Security answers are cached for an hour in process** (`appStatus`, `appDepList`,
   `inheritanceOrder`). Java caches them in Caffeine for an hour and in Redis with no expiry, so
   Java may keep a stale answer until something evicts it; ui-engine refreshes within the hour.
5. **The draft filler cache is keyed per surface.** Java's `UIFillerCache_<app>_<app>_FILLER_READ`
   has no draft dimension, so a draft read and a live read share one entry and whichever comes
   first answers both. ui-engine keys draft reads `<client>:draft` in the same cache name, so
   Java's evictions (`:*`) still clear both.

## JSON

6. **Key order of maps.** Java writes every map as a `java.util.HashMap` (its copy constructors
   rebuild them), so the key order is the table order: by `String.hashCode()` bucket, then by
   insertion within a bucket. ui-engine reproduces that (capacities by puts and by copy
   constructor), so most responses are byte-identical. Within a bucket, the insertion order of a
   merged map is not stable in Java: the merge runs on a scheduler and keys land as their merges
   finish, and Java instances that load an object from Redis rebuild its maps with different
   capacities. ui-engine puts keys settled on the spot first and merged keys after, in visiting
   order. The parity script compares values and reports key-order differences separately.
7. **Stored dates.** Java writes a stored date as `LocalDateTime` epoch seconds read in the
   JVM's zone, which shifts the number by the JVM's UTC offset. ui-engine applies the configured
   `ui.java_zone_offset` (a fixed offset, `+05:30` locally, `+00:00` where the JVMs run in UTC).
   A zone with daylight saving would need the zone's rules; none of the deployments use one.
8. **Untyped values Mongo rarely holds** (dates, ObjectIds, decimals inside a definition's maps)
   are written as ISO strings / hex strings. Java would write a date the same way but an
   ObjectId as Jackson's `{timestamp, date}` bean. None occur in the local `ui` database
   (checked over every collection on 2026-10-15).
9. **`urlDetails`** writes `appCode` then `clientCode`; Java's `Map.of` order changes with each
   JVM start.
10. **A schema's multi-valued `type`** keeps the stored order; Java holds it in a `HashSet` of
    enums whose order changes with each JVM start. The parity script compares these as sets.

## Errors

11. **Error bodies carry no stack trace** (`stackTrace` is empty, as in every Rust unit), and for
    unexpected errors `debugMessage` repeats the message instead of Java's exception text. A
    refusal relayed from security keeps security's status and message; Java's `debugMessage`
    there is Feign's text.
12. **Paths ui-engine does not serve** (anything outside the routes above) are answered as the
    Java `UniversalController` answers a request without `X-Forwarded-Host` (400), and 404
    otherwise, and a method a route does not have (`POST /api/ui/application`) is a 405 with
    `Allow`; Java hands both to `UniversalController`, which ui-shell serves. Route only the
    listed GETs (and the personalization methods) to ui-engine, everything else to ui-shell.

## Robustness

13. **The `baseClientCode` chain is followed at most 32 levels.** Java follows it without a
    bound, so a cycle never finishes there.
14. **Personalization saves update in place on the stored version** (`$set` filtered by
    `version`) instead of replacing the whole document. A save that races another gets the Java
    412 "Please reload..." instead of silently overwriting it; fields the save does not touch
    keep their stored form.

## KIRun built-ins

15. **`includeKIRunRepos=true` is answered from a snapshot.** The built-in functions and schemas
    live in kirun-java, and Java answers `repositoryFind` for them with Gson / Jackson of
    kirun-java's own objects (some of which Java cannot serialize and answers 500). ui-engine
    serves the same names, bodies and 500s from `src/kirun_catalog.json`, captured from the Java
    ui (kirun-java 4.9.2) by `tools/capture_kirun_catalog.py`. Re-run it when the Java services
    move to a new kirun-java.
16. **Repositories across app dependencies** are asked in dependency order (the app first).
    Java asks them concurrently: `repositoryFind` answers with whichever finds the object first
    and `repositoryFilter` lists names in completion order. The parity script compares filter
    lists as sets.
17. **A JSON `null` in a schema's `defaultValue` / `constant`** is treated as absent. Gson reads
    it as `JsonNull`, which Java's Jackson then cannot write (500).
18. **A request without a `clientCode` header** (ui-engine and ui-shell): Java asks security
    without one, security fails, and Java relays a 500. The platform security client sends an
    empty `clientCode`, security answers for an anonymous caller, and the controller's own
    header check answers 400 `Required header 'clientCode' is not present.` Through the gateway
    the header is always set.

## ui-shell

19. **The page's entry scripts are read once, at start** (an `asset-manifest.json` file if
    configured, else `https://<cdnHostName>/js/dist/asset-manifest.json`, else `vendors.js` +
    `index.js`), as Java reads them in `@PostConstruct`. Two instances started on either side of
    a CDN deploy list different scripts (and so give the page different ETags); restart both,
    or call neither, after a deploy. The parity script normalises the script tags.
20. **Its caches are local only**: the index page (`ApplicationCache_<app>_indexNewCache_<app>`,
    per client and surface), the JS files (one cache per path), the route patterns
    (`URIPatternCache`), the analytics answers (`analyticsQueryCache`). Java also writes them to
    the Redis L2; ui-shell never reads or writes the hashes, and Java's evictions (an app saved,
    a URI path saved) reach it on the eviction channel.
21. **`GET /api/ui/internal/cache` and `/stats` describe this instance's caches**, which are not
    Caffeine's: the names are the ones it has used; `hitCount` / `missCount` / `hitRate` count
    since start; `evictionCount` counts entries dropped for size or age; `entries` is Moka's
    estimate; `weightedBytes` is -1 (no weigher). `DELETE /api/ui/internal/cache` walks the
    Redis `cmn-*` hashes as Java does (announce, then delete) and also clears this instance's own
    caches outright, since Rust caches never appear in Redis. Another Rust instance (ui-engine)
    drops only the caches whose names it hears; the rest expire within the hour.
22. **Header names passed to a URI path's function.** Without a `headersMapping`, Java passes
    every request header to the function as a parameter under its own spelling. Hyper lower
    cases header names, so ui-shell restores the spelling of the headers the gateway and the
    proxies set (`appCode`, `clientCode`, `X-Forwarded-Host`, `-Port`, `-For`, `-Proto`,
    `-Prefix`, `X-Real-IP`, `X-appCode`, `X-clientCode`, `X-Full-URL`, `Host`, `Authorization`,
    `Content-Type`) and passes the others lower case, which is how HTTP/2 clients send them
    anyway. A `headersMapping` looks headers up case-insensitively in both, so mapped routes do
    not differ.
23. **Route candidates are tried in inheritance order** (root client first). Java merges the
    clients' pattern lists concurrently and takes the first match to arrive, so when two clients
    both have a matching pattern either can win there.
24. **A request body that is not JSON at all** is a 500 in both; Gson's `debugMessage` (line,
    column, path, troubleshooting link) is not reproduced. A body that is JSON but not an object
    (an array, `null`, a string) gets Gson's exact message, and Gson's lenient forms (unquoted
    names and strings, single quotes, `=`/`=>`, `;`, comments, `)]}'`) are read as Gson reads
    them, numbers kept digit for digit.
25. **`outputEventParamName` with a range (`[1..3]`) or an expression in brackets** is a 500
    with its own message. Paths, indexes (negative ones too), quoted keys and `length` behave as
    kirun-java 4.9.2's `ArgumentsTokenValueExtractor`, its `ExpressionEvaluationException`
    messages included; every route on the local stack uses a plain path.
26. **A Feign error that is not a JSON one** (core or security answering text, or not
    answering) is the generic 500 in both; the `debugMessage` names the call in Feign's words
    but not in Feign's exact text.

## ui-editor

The write path is the `overridable` crate's, so its differences hold here too
(`crates/overridable/DIFFERENCES.md`). The ones a ui caller can see:

27. **The library's security fixes stay.**
    - `create` never takes an id from the body. Java's `repo.save` upserted by the body's `id`,
      so a caller allowed to create in its own client could overwrite any document, another
      tenant's included.
    - The cached list (`_READ_PAGE`) checks access before it is served. Java served a cached
      page to any caller on the same client code, an anonymous one included.
    - Version reads are checked: `POST /api/ui/versions/{id}/query` (unchecked in Java) and
      `GET /api/ui/versions/{id}` both require the type's `_READ` authority, read access to the
      app, and the version's client in the caller's chain.
    - `clientOnly` on a list works. In Java any `clientOnly` value answered an empty page.
    - `DELETE /api/ui?deleteAppCode=` evicts every name's caches, live and draft. Java's per-name
      evictions were never subscribed.
28. **URI path and filler history is read with the application's authorities.** Java's
    `VersionService` has no authority name for `URIPATH` and `FILLER`, so its `GET
    /versions/{id}` refuses their rows to everyone (an empty 200) while its unchecked query
    shows them to anyone. With every version read checked, the editor maps both to
    `Application` (`EDITOR_AUTH_NAMES`): a caller who may read the application sees their
    history through either route.
29. **Evictions Java leaves out are added.** They only make caches fresher; no answer changes.
    - Create of an application, page, style or theme clears the application and page OUI caches
      (and the style's or theme's own) and publishes the SSR invalidation; an application's
      create also clears its index, manifest and properties caches. Java's create clears none,
      so a cached "not found" (or an app's index page) outlived the create.
    - Update clears the UI caches of the stored app as well as of the app the body names (Java
      keys them on the body's `appCode`, which an update cannot change).
    - A page component `PATCH` and an event `PUT` clear the page and application OUI caches and
      publish the SSR invalidation. Java's patches clear only the definition caches, so the
      engine kept serving the page from before the patch.
    - Delete clears every client's cached copy of the object (`<Cache>` and `<Cache>_DRAFT`, all
      keys). Java evicts only the deleting client's key, so a derived client's cached merge
      kept serving a deleted base.
    - A filler's draft save, draft discard and fork clear its `FILLER_READ` cache (the library's
      item 7).
30. **Spring's own 400s** (an unreadable body, a missing or unconvertible parameter, a missing
    header) are written as Java's `ControllerAdvice` writes them: the generic message with an
    exception id and Spring's text as the debug message. For a missing forwarded header on the
    wipe or a transport import, the debug text does not name the header.
31. **Order.** An export's objects come in service order; Java reads the services concurrently
    and writes them in whatever order they finish (the library's item 8).
32. **A `NullPointerException` in Java** (a function or schema without a `definition`, a URI
    path without `pathDefinitions`, a component patch without `componentData`) is the same 500
    with the generic message; the debug message is not the JVM's text.
33. **The Android keystore is built without a JDK.** A new mobile app gets a JKS keystore
    (`0xFEEDFEED` v2, the `KeyProtector` key encryption, a SHA-1 integrity seal) holding a fresh
    RSA 2048 key and a self-signed SHA256withRSA certificate with Java's subject (`CN=Modlix
    Team, OU=Mobile Development, O=Modlix, L=Karnataka, ST=Karnataka, C=IN`), alias `modlix`
    and validity, and random store and key passwords as Java makes them. `keytool` reads it
    (the ignored `keytool_reads_it` test). The certificate carries no extensions, as Java's.
34. **Paths and methods the editor does not serve** are answered as ui-engine answers them
    (item 12): a 400 without `X-Forwarded-Host`, a 404 with it, and a 405 with `Allow` for a
    method a route lacks (`PATCH /api/ui/pages`); Java hands both to `UniversalController`. The
    engine's `repositoryFind` / `repositoryFilter` routes are not here: on ui-editor
    `GET /api/ui/functions/repositoryFind` would read a function with that id (a 404). Route
    them to ui-engine first.
35. **App Store Connect** is called with the same requests and error handling, from the
    `editor.apple_*` settings (`MODLIX__EDITOR__APPLE_API_KEY_CONTENT` for the key); nothing is
    configured locally, where `GET /api/ui/applications/apple/certificates` is an empty 500 in
    both.
36. **Key orders Java picks per JVM run.** A `Page`'s properties, its `pageable` and its sort
    orders are written in the order Jackson finds their getters, which is `getDeclaredMethods`
    order, and HotSpot sorts methods by symbol address: the same jars give a different order after
    a restart (measured on 2026-10-15: the Java ui restarted at 21:01 moved `last`, `sort` and
    `first`). Rust writes one fixed order; `tools/parity_ui_editor.py` reports a difference in
    only these orders as expected.
37. **The seed of a client's first copy** (`PageService.createForTarget`, the page as the
    target's base client sees it) is read without the definition cache's clone, through the
    read's own steps. The clone gives every component the class's full shape, which the
    difference extraction would see as changed, storing every component instead of the one
    changed; Java compares beans, where the two are equal. The `forbiddenPage` and permission
    rules of `applyChange` are applied to the seed as Java applies them.
