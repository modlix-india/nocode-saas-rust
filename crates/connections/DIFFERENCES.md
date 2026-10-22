# crates/connections compared with the Java core

Measured against `nocode-saas/commons-core` (and `commons-mq`) on 2026-10-15 with JDK 21 and
the local core's classpath. The scratch harnesses ran the Java classes on recorded cases, and
the outputs are fixtures under `tests/fixtures/*_java21.*`. The tests compare them:

| Area | Java run on | Compared in |
|---|---|---|
| `OutboundUrlUtil` | 1982 vectors (1116 save-time, 866 call-time), with the DNS answers Java saw | `tests/java_parity.rs`, `tests/outbound_url_util.rs` |
| `java.net.URI` parsing | the `java_uri_cases` corpus | `java_uri_parser_matches_java` |
| `InetAddress` literals | the `inet_cases` corpus | `inet_literals_match_java` |
| Spring `UriComponentsBuilder` / `DefaultUriBuilderFactory`, all 5 encoding modes | two corpora (`uri_vectors`, `uri_vectors2`) | `java_parity.rs` |
| `BasicRestService.call` | 66 cases against a local echo server; requests as the server saw them, and the `RestResponse`s | `tests/rest_parity.rs` |
| FreeMarker 2.3.32 | three corpora | `java_parity.rs` |
| RabbitMQ message bodies and properties | `EventQueObject` and `NotificationQueObject` | `tests/mq_messages.rs` |
| `core_tokens` SQL | jOOQ 3.x rendering of every DAO statement | unit tests in `src/tokens.rs` |

Everything in those runs is the same except what is listed here.

## Stricter than Java on purpose (security)

1. **The guard also checks the host the Rust HTTP client connects to** (`outbound::guard_target`).
   Java's guard and Java's client both read a URL with `java.net.URI`, so they always agree on
   the host. Rust's client reads it with the `url` crate (WHATWG rules), which accepts and
   rewrites inputs that `java.net.URI` does not. After Java's rules pass (ported exactly as
   `validate_resolved`), the same rules run again on the `url` crate's host, and an
   IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is judged as the IPv4 address it carries.
   Over the 866 call-time vectors (`guard_target_against_javas_vectors`) this allows nothing
   that Java refuses, and refuses exactly one URL that Java allows: `http://0177.0.0.1/`.
   Java reads `0177` as decimal (177.0.0.1, public). The `url` crate reads it as octal
   (127.0.0.1), and that is where the Rust client would connect. With the guard off (local
   development only), Rust connects to 127.0.0.1 for that URL. What Netty connects to in Java
   was not measured.
2. **Private DNS answers are refused when connecting, not only in the guard.** Java resolves the
   name once in `validateResolved` and Netty resolves it again to connect, so a name that
   changes its answer between the two lookups (DNS rebinding) passes. Here the HTTP client
   resolves once, and with `block_private_targets` on it never connects to a non-public
   address. The refusal reads `'<host>' resolves to <ip>, which is a private or internal
   address`.
3. **OAuth2 token endpoints are guarded.** Java calls `tokenDetails.url` and the refresh-token
   URL without `OutboundUrlUtil`. Here they go through `guard_target` like every other
   connection URL, when `block_private_targets` is on.
4. **Scoped IPv6 literals that name an interface** (`[fe80::1%en0]`) are treated as names that
   do not resolve, without looking up the machine's interfaces. Java binds them to the
   interface, which makes them link-local and therefore refused. Both sides refuse; the message
   differs (`does not resolve` instead of `private or internal`). Numeric scopes are ported
   exactly.
5. **The REST timeout also covers waiting for the response head.** Java applies `.timeout(...)`
   only to reading the body (`handleResponse`), so a server that accepts the request and never
   answers keeps a Java call waiting forever. Here the same duration bounds the response head,
   and then the body, with Java's timeout message
   (`Did not observe any item or terminal signal within Nms ...`).
6. **A TLS handshake is bounded at 10 s** (Reactor Netty's default handshake timeout, which a
   plain `rustls` connect does not have).

## Behaviour fixed on purpose

7. **An empty 2xx from SendGrid counts as sent, once.** In Java, SendGrid's normal answer, an
   empty `202`, completes `bodyToMono(String)` empty, so `.map(e -> true)` never runs.
   `SendEmail` then falls into its `switchIfEmpty` and **sends the mail a second time** with
   the raw app and client codes, and the function ends without output. Here any 2xx returns
   `true`, and the mail is sent once.
8. **Decimals keep double precision.** Java converts KIRun arguments with kirun-java
   `JsonUtil.toMap` → `PrimitiveUtil.findPrimitive`, which turns a decimal parsed from JSON
   into a `Float` when it fits. This applies to the REST JSON body, `SendEmail` template data
   and `CreateEvent` data. In Java, `3.14159265358979` is sent as `3.1415927`, `1234567.891`
   is sent as `1234567.9` (Jackson), and a template prints it as `1,234,567.875` (checked in
   JDK 21). Values computed inside KIRun are not narrowed in Java either. A `serde_json::Value`
   cannot tell the two kinds of value apart, so the library keeps the double.
9. **The SMTP read timeout is applied to each command.** `mail.smtp.timeout` is JavaMail's
   socket read timeout. lettre has no such setting, so the same duration bounds each command
   and its reply (connect, STARTTLS, AUTH, MAIL, RCPT, DATA, the message, QUIT), and an expiry
   reads `Read timed out`. `mail.smtp.connectiontimeout` is lettre's connect timeout, as in
   JavaMail. When `mailProps` set neither (or a value of 0 or less), both are 60 seconds
   (2026-10-22; JavaMail waits forever). The message itself may take one more second for every
   100 KiB it carries, so large attachments are not cut off by the per-command timeout.

## Same shape, different text or bytes

10. **Request header names go out in lower case** (`content-type`, not `Content-Type`), because
    hyper writes them that way. Values, header order and bodies matched Java byte for byte in
    all 66 recorded REST cases (the multipart boundary is random on both sides). Header order
    is not proven beyond those cases. **Response** headers keep the server's case and order,
    and are folded as Netty folds them (case-insensitive, first value wins), so the
    `headers` a KIRun step reads are the same.
11. **Non-ASCII characters left in a request target are sent percent-encoded as UTF-8.** The
    URI is built exactly as Java builds it, and in the URI corpus `NONE` and
    `MANUAL_VALUES_ENCODED` keep such characters (`/users/café`). hyper cannot put a non-ASCII
    request target on the wire, so the characters are encoded as they are written. What
    Netty writes for them was not captured: no REST parity case has one.
12. **Error message texts that come from the JVM's libraries are not reproduced**. These are
    Gson's parse errors on a malformed JSON response (`com.google.gson.JsonSyntaxException: ...`
    is kept as the prefix; the rest is serde's text), Netty's connection errors (refused,
    reset, TLS), JavaMail's (`Unable to send the email: <reason>` keeps the prefix, and the
    connect failure keeps `Couldn't connect to host, port: H, P; timeout T;`), FreeMarker's
    parse and render errors, and the OpenAI SDK's. Messages the platform writes itself
    (`messages.properties`, `OutboundUrlUtil`, `Exceeded limit on max bytes to buffer`,
    WebClient's `Content type '...' not supported for bodyType=...`, the timeout above) are
    the same.
13. **A JSON number as the whole REST response** keeps the parsed value, not its text: `1.50`
    comes back as `1.5` (Java's `JsonPrimitive` keeps the lazily parsed `1.50`). Numbers
    inside objects and arrays become doubles as Gson's `Object` reads do (`1` → `1.0`),
    which is the same.
14. **SMTP message formatting is lettre's.** The headers JavaMail writes (`Message-ID`, `Date`,
    `MIME-Version`, the `Content-Type` charset parameter, `Content-Transfer-Encoding`) differ in
    form, and the EHLO name is `mail.smtp.localhost` or `localhost` (JavaMail uses the
    machine's canonical host name). From, To, Subject and the HTML body are the same. Recipient
    handling follows JavaMail exactly: the RCPT reply classes, `mail.smtp.sendpartial`, RSET
    when everything is refused, and OCI's `254` for a suppressed address counting as invalid.
15. **SendGrid's body keys** go out as `personalizations, from, subject, content`. Java builds
    the body with `Map.of`, whose iteration order changes with every JVM start, so no single
    order is Java's.
16. **OpenAI requests** carry `Authorization`, `Content-Type` and `Accept`, and the body the SDK
    sends (`{"messages":[{"content":...,"role":"user"}],"model":"gpt-4o-mini"}`). The SDK's own
    client headers (`X-Stainless-*`, its User-Agent) are not sent. Retries follow the SDK's
    defaults: 2 retries on connection failures, 408, 409, 429 and 5xx, with a backoff of 0.5 s
    doubling up to 8 s. There is no jitter, and `Retry-After` is not honoured. The base URL is
    configurable (`ConnectionsConfig::openai_base_url`) so that tests use a local mock. The
    SendGrid URL is configurable for the same reason. The real endpoints are the defaults.
17. **FreeMarker covers what the stored templates use**, not the whole language (the list is in
    `src/template.rs`). A template that uses anything else fails to render, with a message that
    names the feature, instead of rendering something different. The unsupported features are:
    - `<#assign>`, macros and `<@...>`
    - `${}` inside string literals
    - `?seq_contains` and the other built-ins not listed in `src/template.rs`
    - scientific `?string` patterns
    - ranges, method calls and hash literals
    - `#{...}` with a format spec (plain `#{x}` is supported, as `?c`)
    Everything supported matched Java character for character in the three corpora, white space
    stripping and number formatting included.
18. **The `core_tokens` DAO assumes UTC sessions and a configured Java zone.** Java writes
    `LocalDateTime.now()` (the JVM zone's wall clock) through a `serverTimezone=UTC` session,
    so the column holds that wall clock. The Rust pool also runs in UTC
    (`platform::db::mysql_pool`), and "now" is computed with
    `ConnectionsConfig::java_zone_offset_seconds`. When both run, the offset must equal the
    Java core's zone, or the expiry comparisons shift by the difference.

## Java behaviour kept as it is (worth a decision, not changed here)

19. **A REST connection URL with a path-parameter template (`/x/{id}`) is refused when
    `block_private_targets` is on.** `validateResolved` runs on the template, and
    `java.net.URI` rejects `{`. Java's own output for this case is in the replay fixture.
20. **`application/x-www-form-urlencoded` values are sent as their JSON text**, quotes included
    (`grant_type=%22client+credentials%22`), as `getURLFormDataFromJson` does.
21. **Responses with an `application/*` type other than JSON** (`application/xml`,
    `application/pdf`, ...) come back as a byte array, which a KIRun step sees as an array of
    signed bytes, as Gson writes `byte[]`.
22. **`processAndSendNotification` overwrites the message's `clientCode` with `urlClientCode`.**
23. **Client-credentials tokens are stored under the connection's client and app**, but they
    are looked up under the caller's. When the two differ (a connection inherited from another
    client), every call mints a new token.
24. **Only `OPENAI` AI connections work.** `GEMINI`, `CLAUDE`, `GROK` and `DEEP_SEEK` are refused
    as `Connection details missing <subtype>`, as Java has no service registered for them.
25. **`SendEmail` takes attachments** (Rust only, 2026-10-22; Java sends none). Each value of
    the `attachments` argument is a stored file's URL (`/api/files/{static|secured}/file/...`),
    a `data:` URL, or an object with `url` or `content` (base64 or a `data:` URL) and optionally
    `name` and `contentType`, so a files `FileDetail` such as `TemplateToPdf`'s `fileData` can
    be passed as it is. Stored files are read through the files service's `convertToBase64` as
    the caller's client (else the URL's), as `FileToBase64` reads them; the files service checks
    that this client manages the file's client. They are read only after the connection and
    the template are found and rendered. A file that cannot be read, a URL that is not a stored
    file, or more than 20 MB of attachments in all fails the send (`Unable to send the email:
    ...`). SMTP sends `multipart/mixed` (the HTML body, then each attachment). SendGrid gets
    `attachments` after `content`, and only when there are some. The event action
    (`SendEmailTask`) and the notification service still send none.
26. **A template's language always resolves** (2026-10-22). The rendered `languageExpression`,
    else `defaultLanguage`, else `en`. Java failed on a `defaultLanguage` without an
    expression (it rendered the null expression), and had no language when the expression
    rendered blank without a default. The part set is found in any case (`EN` finds `en`)
    before falling back to the first set. This covers `SendEmail`, the event email action and
    `TemplateToPdf`.
27. **SMTP hosts follow the private-target guard** (2026-10-22; Java connects anywhere). With
    `core.rest.blockPrivateTargets` on (the default), an SMTP host must not be a blocked name
    (`localhost`, metadata hosts, `.internal`, `.local`, ...) and every address it resolves to
    must be public; the connection then goes to exactly the addresses checked, so a second DNS
    answer cannot rebind it. A refusal is `CORE.PRIVATE_TARGET_REFUSED` (`Refusing to call
    "smtp://host:port": ...`). The notification service applies the same rule
    (`email.blockPrivateTargets`, on by default), where, as with any SMTP failure there, it is
    logged and the mail is not delivered.

## Error codes (2026-10-17)

Every `GenericException` this crate raises (`ConnError::Generic`) carries the core catalogue's
code (`CORE.*`, `crates/core/messages/en.toml`, which this crate registers too): the Java bundle
keys by their own codes, the cases of one key by more specific ones (a mail or AI connection of
the wrong provider, a REST connection whose details cannot be applied), and the literal texts
(the private-target guard, OAuth refusals, base64 form parts) by codes whose `java_text` is
Java's. Java's text is unchanged in `message()` and goes to the answer's `debugMessage` (see
core's DIFFERENCES.md, "Error bodies").
