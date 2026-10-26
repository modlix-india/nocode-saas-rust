# files-serve and files-manage compared with the Java files service

Measured against `nocode-saas/files` on the local stack: `tools/parity_files.py` (reads, Java
8003 against files-serve 8103) and `tools/parity_files_manage.py` (everything else, Java 8003
against files-manage 8104, with files-serve 8103 for the cross-service reads). Every case is
SAME or one of the EXPECTED differences below.

## Error bodies: coded, plain-language messages (both units, 2026-10-17)

Every JSON error carries a stable code and a message written for the person reading it, from
the catalogue in `messages/en.toml` (codes `FILES.*`, `src/errors.rs`) and the platform's
(`COMMON.*`). Statuses are Java's (or the ones listed below), unchanged; so is the 404-vs-403
split. A missing file's empty 404 stays empty.

| | Java | files units |
|---|---|---|
| `message` | the bundle text (`Permission to SECURED resource in the path FIN/a.pdf is forbidden`) | the catalogue text in the request's language (`You don't have access to FIN/a.pdf.`) |
| `debugMessage` | the same text, or the exception's | Java's text under its key (`[forbidden_path] Permission to ...`); the literal text for a refusal Java words without a key; Spring's text for a binding error; the cause for a 500 |
| added fields | none | `code`, `action`, `params` (the values, as words), `locale` |
| Spring Security's refusal (anonymous, or a credential security turns down) | empty 403 | 403 `COMMON.SIGN_IN_REQUIRED` ("Please sign in to continue.") or `COMMON.SIGNED_OUT` |
| a parameter that does not bind, a body that cannot be read | 500 "Please try again" (see below) | 400 `COMMON.PARAM_MISSING`, `PARAM_INVALID` or `BODY_UNREADABLE`, naming the parameter |
| 500s | "Please try again. A server error - <id>" | `COMMON.INTERNAL_ERROR`, "Something went wrong on our side. Error id <id>: give it to support." |

- One key, several meanings: `forbidden_permission` naming an app's owner or a client's manager
  answers `FILES.APP_OWNER_REQUIRED` / `FILES.CLIENT_MANAGER_REQUIRED`; `unknown_error` for an
  internal read of a folder `FILES.FILE_IS_FOLDER`, for a missing copy source
  `FILES.COPY_SOURCE_MISSING`; `unable_to_convert` for a folder `FILES.FOLDER_NOT_CONVERTIBLE`.
- A background job's recorded failure keeps Java's text (`errors::java_message`).

## Same on purpose (reproduced, including quirks)

- Paths are resolved from the raw URI exactly as `resolvePathWithClientCode` /
  `resolvePathWithoutClientCode` / `makeTuple` do (first occurrence of the marker, one decode,
  `+` as space, cut at `?`, one trailing `/` dropped). Listing, upload and creation responses
  carry the same `filePath` / `url` (`URLEncoder` encoding, `//` collapsed by the getters).
- JSON bodies are byte-for-byte Jackson's: `INDENT_OUTPUT`, `NON_EMPTY` (an empty `content`
  array, an empty `path`, nulls are left out), property order, Spring's `Page` shape
  (`content, pageable, last, totalPages, totalElements, first, numberOfElements, sort, size,
  number, empty`) and `PageableExecutionUtils` totals. Text answers (`createKey`, base64,
  `aiUploader`, `populate`) are `text/plain;charset=UTF-8`.
- `Pageable` binding: page 0, size 20 (max 2000), unreadable numbers read as 0, `sort=a,b,desc`.
- Listing order: folders first then name; only `type`, `name`, `size`, `lastModified`,
  `created` can be sorted on; the plain first page (unsorted, no filter, size 200) is cached in
  `fsPathList-<TYPE>-<client>`.
- Read access: access path rules with `LIKE` on `PATH` (so `%` and `_` in a rule are
  wildcards), the static "a client without static rules reads everything" fallback, the
  `_withInSubClient` / `_allSubClients` static folders, the secured special folders.
- Write access: `hasWriteAccess` including the system client's `validClientCode` check and the
  `_withInClient` + `ROLE_MobileApp_UPLOADER` shortcut.
- Upload: only the first `file` part is stored (Java's `stream().map().findFirst()`); `name`
  keeps the uploaded extension (`x` + `a.png` is `x.png`, `x.jpg` + `a.png` is `x.jpg.png`);
  static overwrites by default, secured does not; a refused overwrite answers the existing row.
- Delete: the object at the exact key, then the row (the foreign key removes the rows under a
  folder). Deleting a folder leaves the objects under it in the bucket, as Java does.
- `FileNameUtil.validate` on every created name, with Java's messages.
- `createKey`: Java's `base36UUID` (32 random bits, 12 or 13 characters), the raw (still
  encoded) path stored, `ChronoUnit` names case-sensitive, the default 365 DAYS, the
  `time_unit_error` / `time_span_error` rules, no file existence check.
- Access paths: the generic data controller's create (de-duplicated on path, client, type and
  access name, merging write and sub path access), read, page filter from query parameters,
  `POST /query`, PUT, PATCH (reflection-like: only who/path/write/subpaths change), DELETE
  (204 with a JSON content type); `ConditionUtil` / `AbstractDAO` filter semantics including
  `IN` splitting with its escaped-comma quirk and `isValueField` comparing a field with itself.
- Retention policies: list, create, update, delete, effective, preview and the sweep, with the
  resolver's order (own SELF row, nearest manager's MANAGED row, APP row) and the same caches
  (`filesRetentionPolicies`, `filesRetentionHierarchy`) evicted on every write.
- Every write evicts `fsPathExists-`, `fsGetDetail-` and `fsPathList-<TYPE>-<client>` with
  `CacheService::evict_all_everywhere` under the configured prefix (`cmn`), so Java instances
  and files-serve drop them too (checked both ways by the parity script).
- `cleanupExpired` scoped by `TYPE` (the Java source already filters by type; the brief's
  "static cleanup deletes secured rows" is fixed in the Java source this port follows), object
  first and row second, a failure logged and skipped.
- Billing metering: GB with six decimals rounded half up, the date sent as the epoch seconds of
  its UTC midnight (`CommonsSerializationModule`), windows of 900 s in the process's zone.
- Public routes are the same as Spring Security's: `/api/files/static/file/**`,
  `/api/files/internal/**`, `/api/files/secured/downloadFileByKey/*` and
  `/api/files/generic/internal/fs/populate`; anything else needs a signed-in caller (an empty
  403 otherwise). `populate` stays unauthenticated like every `/internal/` route: nginx's
  `location ~/internal` keeps all of them off the internet.

## Different on purpose

### Already in files-serve

- An unknown `downloadFileByKey` key is a 404 `invalid_key`; Java dereferences the missing row
  and answers 500.
- A file whose row exists but whose object is gone from the bucket (S3 `NoSuchKey`, as after
  a database copy without the bucket) is a 404 `object_not_found` ("File with id <path> not
  found"); it was a 500. The FileBrowser fetched secured thumbnails of such files and every 500
  broke the page (local, 2026-10-22).
- A bad query value (an unknown `fit`/`gravity`/`format`, a non-number `width`) is a 400; Java
  answers its catch-all 500.
- An unsatisfiable `Range` is a 416 with `Content-Range: bytes */<len>`; Java's 416 is eaten by
  its own security filter and arrives as a 403.
- Multi-range responses are correct `multipart/byteranges`; Java's have no blank line after a
  part's headers and every part after the first is empty.
- `format=webp` produces a WebP; Java has no WebP writer and sends an empty body.
- A non-ASCII download name gets an RFC 5987 `filename*` next to an ASCII `filename`.
- Error bodies have an empty `stackTrace` and are coded (see Error bodies above); Java sends
  its full stack and the exception's own message (internal class names, SQL) to any caller.
- The disk copy of a downloaded object is named after its version (`UPDATED_AT`), so a write
  on any instance is picked up by every Rust instance through the `fsGetDetail` eviction. A
  Java instance keeps one unversioned copy and drops it only on its own writes, so after a
  write elsewhere it serves the old bytes (with the new ETag) until it restarts or is asked
  with `noCache=true`; the parity script shows this for a files-manage write read through Java.

### New in files-manage

- **Write access checks Java does not make**: `POST /directory/**`, `POST /import/**` and
  `POST /static/copyToClientPage` (on `sitezump/<pageName>`) require the same write access as
  an upload. In Java any signed-in user could create folders, import zips into, or copy into
  any client's tree by naming it in `clientCode`.
- **Unknown client codes** (`clientCode=NOPE`) are a 403 `forbidden_path` (listing, delete,
  upload, export) or `forbidden_permission` (access paths); Java fails with a 500 on the
  `null` client.
- **Binding errors are 400s**: a missing required parameter or part (`file`, `clientCode`,
  `fileName`, `pageName`, `filePath`, `url`), a non-number id or limit, an unknown enum
  (`fileType`, `timeUnit`, `resourceType`, sort direction), an unreadable JSON body, an
  invalid `Query` page/size. Java's `ControllerAdvice` turns every binding error into a 500.
- **Missing upload file** (`POST /**` without a `file` part) is a 400 `file is/are missing`;
  Java fails with a `NullPointerException` (500).
- **`metadataRequired` absent** on `GET /internal/{type}/convertToBase64` reads as false; Java
  unboxes the `null` and answers 500.
- **A missing file** for internal base64 is an empty 404; Java dereferences `null` (500).
- **The file name is checked before the object is written**: Java writes the object, then
  refuses a blank or reserved name (400) and leaves an object no row points at.
- **Cache eviction after the row is written** (Java evicts between the object write and the
  row write, so a read in between re-caches the old row for an hour).
- **Zip jobs record how they ended**: DONE only after every file is written and the caches are
  evicted, ERROR with the message when the job fails. Java marks an import DONE as soon as the
  uploads are queued (before they run) and leaves a failed import or export PENDING for ever.
- **Zip entries outside the target folder** (`../x`, absolute names) are skipped; Java writes
  them wherever the entry name points on the server's disk.
- **Content type of zip-imported objects** is set from the name; Java sends none (R2 stores
  `application/octet-stream`), which matters only to something reading the bucket directly.
- **Keys**: a `createKey` collision on the unique key column is retried with a new key (Java
  fails the request); `FOREVER`/`ERAS` or an overflowing span is a 400 (Java 500). A span of
  `-9223372036854775808` `MONTHS` overflowed its own negation (a panic in a debug build, the 400
  only by wrap-around in release); fixed 2026-10-15, with a test.
- **Raw internal uploads** stream the body to disk and use its real length, so a chunked body
  (no `Content-Length`) works; Java passes `-1` to S3 and fails.
- **Images**: `transform`, `generic/client`, `generic/user` and `generic/resize` use Java's
  geometry (Scalr AUTOMATIC fit, rotation canvas, crop offsets and fill), but pixels and file
  sizes differ (Lanczos3, a different PNG/JPEG encoder). A non-number image part is a 400
  (Java 500). An image with alpha written as JPEG is laid over black (Java fails to write it
  and answers 500). `generic/resize` of anything but jpg/jpeg/png is a 400 (Java 500, no enum
  constant). A missing `Client_UPDATE` for `generic/client` is a 403 `forbidden_permission`
  (by reading the code: Java's `ControllerAdvice` turns the `AccessDeniedException` into a 500;
  not observed, no local user lacks the authority).
- **Access paths**: a client-supplied `createdAt`/`updatedAt` in a create body is ignored (the
  database default applies; Java writes the value). `GET /api/files/accesspath` without any
  query parameter works (Java has no condition and fails with a 500). The internal create
  without `clientCode` is a 400 (Java fails the NOT NULL column, 500).
- **`copyToClientPage` with a missing source** answers Java's 500 `Internal Server Error
  (Unknown)` (kept), but the copy uses a one-off download instead of the shared disk copy.
- **Timestamps of rows** (`createdAt`, `updatedAt` of access paths, jobs, retention policies)
  are the true instant. Java reads a `TIMESTAMP` into a `LocalDateTime` in the JVM's zone and
  Jackson writes it as if it were UTC: on a JVM outside UTC (the local IST one) Java is off by
  the zone offset (+19800 s). The Java services run in UTC containers, where the two agree.
- **Method mismatch** on a known path is an empty 405; Spring's `ControllerAdvice` answers
  500.
- **Transform without multipart** is an empty 415; Java 500.

- **The admin purge (new, 2026-10-26, no Java counterpart).** `DELETE /api/files/purge/client/{clientCode}`
  and `DELETE /api/files/purge/app/{appCode}` on files-manage, `dryRun` true unless `dryRun=false`,
  called by multi's purge. A client: every object under `<client>/` in both buckets, its
  `files_file_system` rows, its access paths, upload records, retention rules and the secured
  access keys under `<client>/`; only by a client that manages it (security's
  `doesClientManageClientCode`) with `Client_DELETE`, never by itself, never SYSTEM. An app:
  every root folder named exactly the app code, under every client and in both buckets, with
  its objects and rows, and the app's retention rules; SYSTEM with `Application_DELETE` only.
  Answers `{dryRun, objects: {STATIC|SECURED: n}, rows: {table: n}, errors}`; refusals are
  `FILES.PURGE_FORBIDDEN` (403) and `FILES.PURGE_BAD_CODE` (400).

## Known, kept

- Only 32 bits of randomness in a secured access key (`base36UUID`).
- Deleting a folder orphans its objects in the bucket (the row cascade removes the tree).
- A same-second overwrite keeps the same `UPDATED_AT`, so other instances keep their disk copy
  of the previous bytes (version = whole seconds). Java has the same ETag problem.
- The fsGetDetail cache of other instances is evicted by message, not by content: an instance
  that misses the eviction (Redis down) serves cached rows for up to an hour, as Java does.
