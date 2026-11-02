# Lighthouse's config server compared with the Java config server

Measured with `tests/spring_config.rs`: the Java config server (`nocode-saas/config`, native
profile) served the synthetic fixture in `tests/fixtures/oci-config`, its answers are the
goldens in `tests/fixtures/spring`, and Lighthouse answers the same bytes for every one of them
(15 requests: several apps and profiles, a label, two profiles at once, YAML 1.1 typing,
anchors and merge keys, multi-document files, `${...}` left as is). A YAML file Spring refuses
(a duplicate key) answers 500 with Spring Boot's error body on both.

`lighthouse render` writes byte for byte what `tools/render_config.py` writes, with the same
report and exit status (`tests/units_render.rs` on the fixture for dev, stage and prod; on the
real oci-config checked locally with `cmp`, never printed).

## Different on purpose

- **Only what is configured is served.** The Java server answered any app and any profile to
  anyone who could reach it. Lighthouse serves the apps listed in `[config.spring.apps]`, the
  profiles of `[config.spring] profiles` (default `oci<env>`), and refuses `registry` and `v1` as
  app names. An app's keys can be limited to some prefixes (each source stays, so ssr-server
  still reads the right first source), or folded into one source (`merge_sources`).
- **A token is required** (scope `ai` or `ops`, Bearer or Basic), except for apps marked
  `open` (ssr-server's fetch cannot send one).
- **`version`** is the snapshot's commit (GitHub) or a hash of the files (a directory). The
  native backend answered null.
- **`label`**: only the configured branch or the snapshot's commit is served (404 otherwise);
  the Java git backend could check out any branch.
- **Files**: root `*.yml` only, as oci-config has. Spring also read `.yaml` and `.properties`.
- **Only `GET /{app}/{profile}[/{label}]`**: not the `/{app}-{profile}.yml` and `.properties`
  forms, which nothing in use calls.
- **Source names of a GitHub snapshot** are `<uri>/<file>`, as the git backend writes them;
  for a multi-document file `<uri>/<file> (document #N)`, which could not be checked against
  the git backend (oci-config has no multi-document file).

## Kept from the script, unlike Spring

- `tools/render_config.py` ranks `<service>.yml` below the documents of `application.yml`
  activated for the profile; Spring ranks it above them. The renderer keeps the script's order
  (its output must not change); oci-config has no activated documents, so both agree today.
- The renderer types YAML as the script did (a float needs a dot and a signed exponent, so
  `1e5` stays text; keys are typed even when quoted). The Spring endpoint types it as SnakeYAML.
