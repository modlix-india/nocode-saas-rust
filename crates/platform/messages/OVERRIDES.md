# Error messages: languages and customisation

Every error a Rust unit answers through the catalogue (`platform::messages`) has a stable code
(`SEC.APP_ACCESS_FORBIDDEN`), an HTTP status, named values (`{app}`, `{permission}`...), and per
language a `text` and an optional `action`. This note says how a text is chosen, how to add a
language, how to change a text without a build, and the store planned for per-client and per-app
texts.

## How a text is chosen

1. The request's languages, best first: `Accept-Language` (by q-value), then the signed-in
   user's `localeCode`, then their client's (when the unit knows it), then `[messages]
   default_locale`, then English. Each brings its less specific forms after it (`pt-BR`, `pt`).
2. For each language in turn, the first layer that has a text for the code:
   1. the client's (or client's app's) own text, from the installed `OverrideSource`;
   2. the service's override files (`[messages] override_dir`);
   3. the built-in catalogues compiled into the binary.
3. The first language with a text wins; the `action` comes from the same language (a layer may
   override only the `text` or only the `action`; an empty `action` removes it).
4. A code with no text anywhere reads as `COMMON.ERROR` ("Your request could not be
   completed."), never as an empty message.

The response says which language it used in `locale`.

## The catalogue files

`crates/<crate>/messages/en.toml`, one table per code:

```toml
[SEC.USER_ALREADY_HAVING_APP_ACCESS]
status = 400
params = ["app"]
text = "[You already have access to {app}.|You already have access to this app.]"
action = "Sign in to continue."
java = "user_already_having_app_access"
when = "Asking for access to an app the user can already use."
audience = "signed-in"
```

- `{name}` a value; `{name|default}` a value or the default; `[ ... ]` kept only when every value
  directly inside it is known; `[ ... | otherwise ]` the alternative when one is not; `\{ \} \[
  \] \| \\` the characters themselves. `{errorId}` is the response's error id.
- `params` names the values in Java's `$` order; a kind after a colon changes how a value reads:
  `permission:authority` ("the Edit pages permission"), `what:entity` (a Java class name in
  words).
- `status`, `params`, `java`, `java_text`, `when` and `audience` belong to the English file only.
  The crate tests (`platform::messages::check_catalogue`) refuse a code without a status or text,
  an undeclared placeholder, or one that would print nothing without its value.

## Adding a language

Built in (shipped with the binary): add `crates/<crate>/messages/<locale>.toml` with `text` (and
`action`) for the codes translated so far, and one line in the crate's catalogue module, next to
the English one:

```rust
platform::messages::register("security", "pt-BR", include_str!("../messages/pt-BR.toml"));
```

Codes not yet translated fall back to the next language of the request, then English. The
platform's own codes (`COMMON.*`) and labels (`PERMISSION.*`, `ENTITY.*`, `WORD.OR`) live in
`crates/platform/messages/` and are translated the same way.

Without a build: put `<locale>.toml` (same format, `text` and `action` only) in the directory
named by `[messages] override_dir` (or `MODLIX__MESSAGES__OVERRIDE_DIR`) and restart the unit.

## Changing a text without a build

The same override directory: `en.toml` there with only the codes to change replaces those texts
for that service, in every request whose best available language is English. The file is read at
start; a file that does not parse stops the unit from starting, so a typo cannot ship silently.

## Per client and per app (planned)

The hook exists and does nothing yet: `platform::messages::OverrideSource`, installed with
`platform::messages::set_override_source`, is asked after the handler for each language of the
request (up to the one the built-in text was found in), with the client whose site the request
is on (the `clientCode` header, else the caller's own client), the `appCode`, the language and
the code. The first text it returns replaces the body's `message` (and `action`, when given); the
code, status, values and `debugMessage` stay.

The store planned behind it:

- **Where**: a table in the `security` schema, next to the clients and apps it is keyed by:
  `security_message_override (ID, CLIENT_ID, APP_ID NULL, LOCALE, CODE, TEXT NULL, ACTION NULL,
  CREATED_BY, CREATED_AT, UPDATED_BY, UPDATED_AT)`, unique on `(CLIENT_ID, APP_ID, LOCALE, CODE)`.
  A row with `APP_ID` null applies to every app of the client; one with an app applies there
  only and wins.
- **Who edits**: security-admin routes under `/api/security/messageOverrides` (list, create,
  update, delete), `@PreAuthorize` `Client_UPDATE`, for clients the caller manages
  (`isBeingManagedBy`), with the same checks as the catalogue tests: the code exists, the
  template parses, every placeholder is one of the code's params.
- **How units read it**: security-internal answers `GET
  /api/security/internal/messageOverrides?clientCode=&appCode=&locale=` with that client's (and
  app's) texts as one map; the platform's `OverrideSource` implementation asks it once per
  (client, app, locale) and keeps the map in a `cmn-messageOverrides` cache, evicted on change
  through `evictionChannel` like every other cache, so a change shows everywhere within a request.
- **Later**: a managing client's texts could apply to the clients it manages (walk the client
  hierarchy, nearest first); and a pane in the app builder to edit them, showing the built-in
  text and its placeholders beside each override.
