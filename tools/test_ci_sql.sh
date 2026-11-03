#!/usr/bin/env bash
# Tests tools/ci_sql.sh end to end with nothing shared: a throwaway MySQL container on its own Docker
# network (no port published, a random root password, removed on exit, whatever happens) and copies of
# sql/ in a temporary folder. It never reaches mysqldev8 or any environment.
#
#   tools/test_ci_sql.sh                  Docker running; pulls mysql:8.4 and the Flyway image once
#   MYSQL_IMAGE=mysql:8.0 tools/test_ci_sql.sh
#
# The sql-check workflow runs it on every change to sql/ or this script.

set -euo pipefail

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
CI_SQL="$ROOT/tools/ci_sql.sh"
MYSQL_IMAGE=${MYSQL_IMAGE:-mysql:8.4}
NAME=ci-sql-test-$$
WORK=$(mktemp -d)

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker network rm "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

passed=0
ok() { echo "ok   $*"; passed=$((passed + 1)); }
die() { echo "FAIL $*" >&2; exit 1; }

# The scratch server's root password: random, never printed, gone with the container. Docker reads the
# variables from this environment (-e NAME without a value), so it is not on any command line either.
FLYWAY_PASSWORD=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
export FLYWAY_USER=root FLYWAY_PASSWORD MYSQL_ROOT_PASSWORD=$FLYWAY_PASSWORD MYSQL_PWD=$FLYWAY_PASSWORD
export CI_SQL_NETWORK=$NAME

sq() { docker exec -i -e MYSQL_PWD "$NAME" mysql -uroot -h127.0.0.1 -N -B "$@"; }
plan() { "$CI_SQL" run plan "$WORK/sql" "$NAME" 2>&1; }
migrate() { "$CI_SQL" run migrate "$WORK/sql" "$NAME" 2>&1; }
pending_of() { grep -E '^pending=[0-9]+$' <<< "$1" | tail -1 | cut -d= -f2; }
files_in() { find "$1" -maxdepth 1 -name 'V*.sql' | wc -l | tr -d ' '; }
databases() { find "$WORK/sql" -mindepth 1 -maxdepth 1 -type d ! -name rollback -exec basename {} \; | sort; }

# --- 1. The archive rules on the tree as it is --------------------------------------------------------
"$CI_SQL" rules >/dev/null || die "rules: the archive breaks its own rules (run tools/ci_sql.sh rules)"
ok "rules hold for sql/ as it is"

# --- 2. The archive rules against a base: a scratch git repository with sql/ committed -----------------
repo="$WORK/repo"
mkdir -p "$repo" && cp -R "$ROOT/sql" "$repo/sql"
rm "$repo/sql/core/V8__"*.sql  # a gap, so V8 can come back as a new file numbered below the base's V9
git -C "$repo" init -q && git -C "$repo" add sql
git -C "$repo" -c user.name=ci -c user.email=ci@localhost commit -qm base
rules_at() { (cd "$repo" && "$CI_SQL" rules HEAD 2>&1); }
expect_refused() {
  local why=$1 want=$2 out
  if out=$(rules_at); then die "rules: accepted $why"; fi
  grep -qF "$want" <<< "$out" || die "rules: refused $why, but not with '$want': $out"
  ok "rules refuse $why"
}
reset_repo() { git -C "$repo" checkout -q -- sql && git -C "$repo" clean -qfd -- sql; }

rules_at >/dev/null || die "rules: refused an untouched base"
ok "rules accept no change against the base"

printf '\n-- edited\n' >> "$repo/sql/files/V3__Path defaults.sql"
expect_refused "an edited file the base has" "never edit, rename or remove it"
reset_repo

git -C "$repo" mv "sql/files/V3__Path defaults.sql" "sql/files/V3__Path defaults renamed.sql"
expect_refused "a renamed file the base has" "never edit, rename or remove it"
git -C "$repo" reset -q && reset_repo

rm "$repo/sql/multi/V1__Initial script.sql"
expect_refused "a removed file the base has" "never edit, rename or remove it"
reset_repo

echo 'CREATE TABLE `core_ci_probe` (`ID` INT PRIMARY KEY);' > "$repo/sql/core/V10__Ci probe.sql"
expect_refused "a new file without its rollback" "no rollback, add sql/rollback/core/V10__Ci probe.sql"
mkdir -p "$repo/sql/rollback/core"
echo 'DROP TABLE IF EXISTS `core_ci_probe`;' > "$repo/sql/rollback/core/V10__Ci probe.sql"
rules_at >/dev/null || die "rules: refused a new file with its rollback: $(rules_at)"
ok "rules accept a new file with its rollback"
reset_repo

echo 'SELECT 1;' > "$repo/sql/core/V8__Late.sql"
mkdir -p "$repo/sql/rollback/core" && echo 'SELECT 1;' > "$repo/sql/rollback/core/V8__Late.sql"
expect_refused "a new file numbered below the base's highest" "V8 is not above V9"
reset_repo

echo 'SELECT 1;' > "$repo/sql/core/V9__Twice.sql"
expect_refused "two files of one version" "more than one file for V9"
reset_repo

echo 'SELECT 1;' > "$repo/sql/core/v10_lower case.sql"
expect_refused "a file not named V<n>__<description>.sql" "not named V<n>__<description>.sql"
reset_repo

# --- 3. Flyway on a throwaway MySQL ----------------------------------------------------------------------
cp -R "$ROOT/sql" "$WORK/sql"
total=0
for db in $(databases); do total=$((total + $(files_in "$WORK/sql/$db"))); done

docker network create "$NAME" >/dev/null
docker run -d --name "$NAME" --network "$NAME" --memory 1g -e MYSQL_ROOT_PASSWORD "$MYSQL_IMAGE" >/dev/null
for _ in $(seq 1 90); do
  # The image's first start runs a socket-only server; TCP answering means the real one is up.
  sq -e 'SELECT 1' >/dev/null 2>&1 && break
  sleep 2
done
sq -e 'SELECT 1' >/dev/null 2>&1 || die "the scratch MySQL ($MYSQL_IMAGE) did not come up"
ok "scratch MySQL $(sq -e 'SELECT VERSION()') up"

out=$(plan) || die "plan on an empty server: $out"
[ "$(pending_of "$out")" = "$total" ] || die "plan on an empty server: expected $total pending: $out"
[ -z "$(sq -e "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ('security','core','files','notification','multi')")" ] \
  || die "plan created a database"
ok "plan on an empty server lists all $total files as pending and changes nothing"

out=$(migrate) || die "migrate from V1: $out"
[ "$(pending_of "$out")" = 0 ] || die "migrate from V1 left files pending: $out"
for db in $(databases); do
  want=$(files_in "$WORK/sql/$db")
  got=$(sq -e "SELECT COUNT(*) FROM \`$db\`.flyway_schema_history WHERE type = 'SQL' AND success = 1 AND checksum IS NOT NULL AND installed_by = 'root'")
  [ "$got" = "$want" ] || die "$db: $got of $want files recorded as applied"
done
ok "migrate builds every database from V1 and records each file as Flyway does"

out=$(plan) || die "plan after migrate: $out"
[ "$(pending_of "$out")" = 0 ] || die "plan after migrate: expected 0 pending: $out"
ok "plan after migrate finds nothing pending"

v1="$WORK/sql/core/V1__Initial script.sql"
cp "$v1" "$WORK/v1.keep"
printf '\n-- edited\n' >> "$v1"
if out=$(plan); then die "plan accepted an edited applied file: $out"; fi
grep -qi 'checksum mismatch' <<< "$out" || die "plan refused the edited file, but not on its checksum: $out"
if out=$(migrate); then die "migrate accepted an edited applied file: $out"; fi
cp "$WORK/v1.keep" "$v1"
ok "plan and migrate refuse an applied file that was edited"

printf 'CREATE TABLE `multi_ci_probe` (`ID` INT PRIMARY KEY);\n' > "$WORK/sql/multi/V2__Ci probe.sql"
out=$(plan) || die "plan with one new file: $out"
[ "$(pending_of "$out")" = 1 ] || die "plan with one new file: expected 1 pending: $out"
grep -q 'Ci probe' <<< "$out" || die "plan did not name the pending file: $out"
[ -z "$(sq -e "SHOW TABLES IN multi LIKE 'multi_ci_probe'")" ] || die "plan applied the new file"
out=$(migrate) || die "migrate with one new file: $out"
[ "$(sq -e "SHOW TABLES IN multi LIKE 'multi_ci_probe'")" = multi_ci_probe ] || die "migrate did not apply the new file"
[ "$(sq -e "SELECT COUNT(*) FROM multi.flyway_schema_history WHERE version = '2' AND success = 1")" = 1 ] \
  || die "the new file has no history row"
ok "a new file is listed as pending by plan and applied once by migrate"

echo "all $passed checks passed"
