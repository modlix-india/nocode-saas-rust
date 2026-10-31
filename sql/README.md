# SQL

Every schema change of the platform databases, in order, one folder per database. Running a folder from V1
upwards on an empty schema builds that database from scratch.

| Folder | Database | History |
|---|---|---|
| `security` | `security` | V1 to V88 from Java |
| `core` | `core` | V1 to V9 from Java |
| `files` | `files` | V1 to V10 from Java |
| `notification` | `notification` | V1 to V4 from Java, V5 push devices (Rust) |
| `multi` | `multi` | V1 from Java |

The Java services (entity-processor, message, worker) are not carried over.

## Rules

- Files are named the Flyway way, `V<n>__<description>.sql`, continuing the numbers above. Each database records
  what ran in its `flyway_schema_history` table, which the Java services filled until the move.
- **Never edit a file once it has run anywhere.** The history keeps a checksum of each file; fix forward with a new
  version instead. The Java files are byte for byte the ones that ran.
- A rollback, when there is one, goes in `rollback/<database>/` under the same name. It is never run by CI
  (Flyway would read a rollback inside the database's folder as a second migration of that version).

## How it reaches dev, stage and prod

`rust-build-deploy.yml` runs `tools/ci_sql.sh` on every deploy, before any unit is replaced: `sql-plan` stops the
deploy if a file that already ran was edited and lists what is pending; `sql-apply` applies the pending files with
Flyway (`flyway/flyway:13.8.1`, on the host), behind the GitHub environment `rust-sql-<env>`. A push that changes
only `sql/` runs the SQL jobs and deploys no unit. To check a folder against local MySQL:

    FLYWAY_USER=root FLYWAY_PASSWORD=... tools/ci_sql.sh run plan "$PWD/sql" host.docker.internal
- A change must work with the release running before it (expand, then contract): add tables, nullable columns or
  columns with defaults, and indexes in one release; drop or rename only in a later release, once no running unit
  reads the old shape. The SQL is applied before the units are replaced, so the old units run against the new schema
  for the length of the deploy.
