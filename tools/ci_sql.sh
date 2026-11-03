#!/usr/bin/env bash
# Applies sql/<database>/V<n>__*.sql to one environment's MySQL with Flyway, for rust-build-deploy.yml.
# Each database keeps what ran in its flyway_schema_history (the Java services filled it until the move),
# so Flyway carries on from there; sql/README.md has the rules for writing a change.
#
#   tools/ci_sql.sh ship <plan|migrate>
#       On the self-hosted runner, from the repository root. Copies sql/ and this script to the host
#       (ENV_NAME, SSH_KEY, SERVER_IP, TAG) and runs `run` there. The database user and password
#       (DB_USER, DB_PASSWORD) go over the SSH session's stdin: never a file, never a command line.
#       plan writes pending=<count> to $GITHUB_OUTPUT when it is set.
#
#   tools/ci_sql.sh run <plan|migrate> <dir> <mysql host>
#       Where Docker runs (the host, or a laptop against local MySQL), with FLYWAY_USER and
#       FLYWAY_PASSWORD set. plan checks every applied file is unchanged and lists what is pending;
#       migrate applies the pending files, database by database, creating a database that is missing.
#       The host may carry a port (host:3307); CI_SQL_NETWORK puts Flyway on that Docker network
#       (tools/test_ci_sql.sh uses both for its throwaway MySQL).
#
#   tools/ci_sql.sh rules [<base ref>]
#       No database. From the repository root: every file is V<n>__<description>.sql with one file per
#       version; against <base ref> (origin/master in the sql-check workflow), no file the base already
#       has is edited, renamed or removed, a new file numbers above the base's highest version, and
#       every new file has its rollback in sql/rollback/<database>/ under the same name.

set -euo pipefail

IMAGE=flyway/flyway:13.8.1
# Every folder under sql/ but rollback/ is one database.
databases() { find "$1" -mindepth 1 -maxdepth 1 -type d ! -name rollback -exec basename {} \; | sort; }

# Docker through sudo, as keepup-rust.sh runs it, when this user cannot reach the daemon (opc on
# stage cannot, on dev it can). sudo resets the environment: keep the two Flyway variables.
DOCKER=(docker)
if [[ $EUID -ne 0 ]] && ! docker info >/dev/null 2>&1; then
  # shellcheck disable=SC2054 # the comma is sudo's list, not an array separator
  DOCKER=(sudo -n --preserve-env=FLYWAY_USER,FLYWAY_PASSWORD docker)
fi

flyway() {
  local dir=$1 host=$2 db=$3 net=()
  shift 3
  [[ $host == *:* ]] || host="$host:3306"
  if [ -n "${CI_SQL_NETWORK:-}" ]; then net=(--network "$CI_SQL_NETWORK"); fi
  "${DOCKER[@]}" run --rm ${net[@]+"${net[@]}"} \
    -e FLYWAY_USER -e FLYWAY_PASSWORD -e REDGATE_DISABLE_TELEMETRY=true \
    -v "$dir/$db:/flyway/sql:ro" \
    "$IMAGE" \
    -url="jdbc:mariadb://$host/" \
    -schemas="$db" \
    -locations=filesystem:/flyway/sql \
    -table=flyway_schema_history \
    -placeholderReplacement=false \
    "$@" </dev/null
}

# The info table without the rows that already ran.
not_applied() { grep -E '^\| (Category|Versioned|Repeatable|Baseline)' | grep -v '| Success ' || true; }

run() {
  local mode=$1 dir=$2 host=$3 total=0 db out pending
  : "${FLYWAY_USER:?FLYWAY_USER is not set}" "${FLYWAY_PASSWORD:?FLYWAY_PASSWORD is not set}"
  for db in $(databases "$dir"); do
    echo "::group::$db"
    if [ "$mode" = migrate ]; then
      flyway "$dir" "$host" "$db" migrate
    else
      # An edited, missing or failed migration stops the deploy here, before anything is applied.
      flyway "$dir" "$host" "$db" "-ignoreMigrationPatterns=*:pending" validate
    fi
    out="$(flyway "$dir" "$host" "$db" info)"
    pending="$(grep -c '| Pending ' <<< "$out" || true)"
    total=$((total + pending))
    echo "$db: $pending pending"
    not_applied <<< "$out"
    echo "::endgroup::"
  done
  echo "pending=$total"
}

ship() {
  local mode=$1
  : "${ENV_NAME:?}" "${SSH_KEY:?}" "${SERVER_IP:?}" "${TAG:?}"
  if [ -z "${DB_USER:-}" ] || [ -z "${DB_PASSWORD:-}" ]; then
    echo "::error::the database user or password secret for $ENV_NAME is not set: the SQL cannot be checked or applied"
    exit 1
  fi
  local dir="/home/opc/rust/sql-ci/$TAG" host="$ENV_NAME-mysql.sub10150624021.modlixvcn.oraclevcn.com" out
  tar -cz sql tools/ci_sql.sh | \
    ssh -i "$SSH_KEY" -o BatchMode=yes "opc@$SERVER_IP" "rm -rf '$dir' && mkdir -p '$dir' && tar -xz -C '$dir'"
  out="$(printf '%s\n%s\n' "$DB_USER" "$DB_PASSWORD" | \
    ssh -i "$SSH_KEY" -o BatchMode=yes "opc@$SERVER_IP" \
    "IFS= read -r FLYWAY_USER; IFS= read -r FLYWAY_PASSWORD; export FLYWAY_USER FLYWAY_PASSWORD; trap \"rm -rf '$dir'\" EXIT; bash '$dir/tools/ci_sql.sh' run $mode '$dir/sql' '$host'" | tee /dev/stderr)"
  if [ "$mode" = plan ] && [ -n "${GITHUB_OUTPUT:-}" ]; then
    grep -E '^pending=[0-9]+$' <<< "$out" | tail -1 >> "$GITHUB_OUTPUT"
  fi
}

# The version of a file name (V012__x.sql -> 12), empty when the name is not V<n>__<description>.sql.
version_of() { [[ $1 =~ ^V([0-9]+)__.+\.sql$ ]] && echo $((10#${BASH_REMATCH[1]})) || true; }

rules() {
  local base=${1:-} bad=0 db f name v status path top
  fail() { echo "::error::$*"; bad=1; }
  for db in $(databases sql); do
    for f in "sql/$db"/*; do
      name=$(basename "$f")
      [ -n "$(version_of "$name")" ] || fail "sql/$db/$name: not named V<n>__<description>.sql"
    done
    for v in $(for f in "sql/$db"/V*.sql; do version_of "$(basename "$f")"; done | sort -n | uniq -d); do
      fail "sql/$db: more than one file for V$v"
    done
  done
  if [ -n "$base" ]; then
    git rev-parse --verify --quiet "$base^{commit}" >/dev/null || { echo "::error::no such ref: $base"; exit 2; }
    # From where this branch left the base, so files the base gained since are not read as removed.
    base=$(git merge-base "$base" HEAD)
    # A rename lists the base's name first: that is the name that ran.
    while IFS=$'\t' read -r status path _; do
      [[ $path == sql/rollback/* || $path != sql/*/*.sql ]] && continue
      [ "${status:0:1}" = A ] && continue
      fail "$path: already in $base and so may have run somewhere; never edit, rename or remove it, add a new version"
    done < <(git -c core.quotePath=false diff --name-status -M "$base" -- sql)
    while IFS= read -r path; do
      [[ $path == sql/rollback/* ]] && continue
      db=$(basename "$(dirname "$path")"); name=$(basename "$path"); v=$(version_of "$name")
      [ -n "$v" ] || continue
      top=$(git ls-tree --name-only "$base" "sql/$db/" | while IFS= read -r f; do version_of "$(basename "$f")"; done | sort -n | tail -1)
      if [ -n "$top" ] && [ "$v" -le "$top" ]; then
        fail "$path: V$v is not above V$top, the highest version $base has for $db"
      fi
      [ -f "sql/rollback/$db/$name" ] || fail "$path: no rollback, add sql/rollback/$db/$name"
    done < <(git -c core.quotePath=false diff --name-only --diff-filter=A "$base" -- sql; git -c core.quotePath=false ls-files --others --exclude-standard -- sql)
  fi
  [ $bad = 0 ] && echo "sql rules: ok${1:+ against $1}"
  return $bad
}

case "${1:-}" in
  ship) ship "${2:?plan or migrate}" ;;
  run) run "${2:?plan or migrate}" "${3:?sql folder}" "${4:?mysql host}" ;;
  rules) cd "$(git rev-parse --show-toplevel)" && rules "${2:-}" ;;
  *) echo "usage: $0 ship <plan|migrate> | run <plan|migrate> <dir> <mysql host> | rules [<base ref>]" >&2; exit 2 ;;
esac
