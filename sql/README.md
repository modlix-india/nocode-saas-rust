# SQL

Every schema change of the platform databases, in order, one folder per database. Running a folder from V1
upwards on an empty schema builds that database from scratch (one exception, below).

| Folder | Database | History |
|---|---|---|
| `security` | `security` | V1 to V88 from Java |
| `core` | `core` | V1 to V9 from Java |
| `files` | `files` | V1 to V10 from Java |
| `notification` | `notification` | V1 to V4 from Java; V5 push devices, V6 push keys, V7 push app keys (Rust) |
| `multi` | `multi` | V1 from Java |

The Java services (entity-processor, message, worker) are not carried over.

**Not quite from scratch:** security V40 looks up a role named `Super Admin` that no file creates (every
environment had it before V40 ran), so on an empty server it stops on a NULL `ROLE_ID`. `tools/test_ci_sql.sh`
puts the role in after V39 as a stand-in. V40 cannot be changed (its checksum has run everywhere).

## Writing a change

1. **Name** it `V<n>__<description>.sql` in the database's folder, `<n>` one above the folder's highest version
   (`sql/core/V10__Event run index.sql`). One file per version; a version below the highest is refused, because
   every environment has already passed it.
2. **Expand, then contract.** The SQL is applied before the units are replaced, so the release already running
   works against the new schema for the length of the deploy, and keeps running on it if the deploy stops
   there. In one release: add tables, nullable columns or columns with defaults, indexes, rows. Drop, rename,
   narrow a column or make it NOT NULL only in a later release, once no running unit reads the old shape. A
   rename is three releases: add the new column and write both, move the reads, drop the old one.
3. **Write its rollback**, required for every new file: `rollback/<database>/` under the same name. It undoes
   the change and says in a comment what is lost (see `rollback/notification/`). When nothing can be undone
   (a data delete), the file is a comment saying so and how to restore from a backup. CI never runs a
   rollback; it is for a person, by hand. It lives outside the database's folder because Flyway would read it
   as a second migration of that version.
4. **Never edit, rename or remove a file once it is on master.** It may have run somewhere; each database's
   `flyway_schema_history` keeps a checksum of every file that ran (the Java services filled it until the move,
   and the Java files here are byte for byte the ones that ran). Fix forward with a new version.
5. **Keep it re-runnable where it is cheap** (`IF NOT EXISTS`, `INSERT IGNORE`, guarded updates), name the
   schema in data statements (`` `security`.`security_v2_role` ``), and look rows up by name or code, never by
   an id from one environment.
6. **Check it** before pushing: `tools/ci_sql.sh rules origin/master` (the rules above) and
   `tools/test_ci_sql.sh` (every database built from V1 with Flyway on a throwaway MySQL container, nothing
   shared touched). The `rust-sql-check` workflow runs both on a pull request and on a push to master.

## How it reaches dev, stage and prod

`rust-build-deploy.yml` runs `tools/ci_sql.sh` on every deploy, before any unit is replaced: `sql-plan` stops the
deploy if a file that already ran was edited and lists what is pending; `sql-apply` applies the pending files with
Flyway (`flyway/flyway:13.8.1`, on the host, the database user from the `<ENV>_DB_USER` / `<ENV>_DB_PASSWORD`
secrets), behind the GitHub environment `rust-sql-<env>` (prod waits for a reviewer, who reads the pending list
in the `sql-plan` log). Units are replaced only after both succeed. A push that changes only `sql/` runs the SQL
jobs and deploys no unit.
